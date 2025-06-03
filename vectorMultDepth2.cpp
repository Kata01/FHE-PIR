#include <openfhe.h>
#include <iostream>
#include <vector>
#include <chrono>
#include <windows.h>
#include <psapi.h>

using namespace lbcrypto;

size_t getMemoryUsage() {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize / 1024;
    }
    return 0;
}

// CLASE CLIENTE
class PIRClient {
private:
    CryptoContext<DCRTPoly> cryptoContext;
    KeyPair<DCRTPoly> keyPair;
    
public:
    void initialize() {
        CCParams<CryptoContextBGVRNS> parameters;
        parameters.SetMultiplicativeDepth(2);
        parameters.SetPlaintextModulus(65537); 
        parameters.SetRingDim(16384);
        parameters.SetSecurityLevel(HEStd_128_classic);
        
        cryptoContext = GenCryptoContext(parameters);
        cryptoContext->Enable(PKE);
        cryptoContext->Enable(KEYSWITCH);
        cryptoContext->Enable(LEVELEDSHE);
        cryptoContext->Enable(ADVANCEDSHE);
    }
    
    void generateKeys() {
        keyPair = cryptoContext->KeyGen();
        cryptoContext->EvalMultKeyGen(keyPair.secretKey);
        
        // Generar claves de rotación para EvalSum
        std::vector<int32_t> indices;
        for (size_t i = 1; i < 16384; i <<= 1) {
            indices.push_back(static_cast<int32_t>(i));
        }
        cryptoContext->EvalAtIndexKeyGen(keyPair.secretKey, indices);
    }
    
    Ciphertext<DCRTPoly> createQuery(size_t index, size_t dbSize) const {
        std::vector<int64_t> selector(dbSize, 0);
        selector[index] = 1;
        Plaintext pt = cryptoContext->MakePackedPlaintext(selector);
        return cryptoContext->Encrypt(keyPair.publicKey, pt);
    }
    
    int64_t decryptResult(const Ciphertext<DCRTPoly>& encryptedResult) const {
        Plaintext pt;
        cryptoContext->Decrypt(keyPair.secretKey, encryptedResult, &pt);
        pt->SetLength(1);
        return pt->GetPackedValue()[0];
    }
    
    CryptoContext<DCRTPoly> getCryptoContext() const { return cryptoContext; }
    PublicKey<DCRTPoly> getPublicKey() const { return keyPair.publicKey; }
    
    // Función para calcular el valor esperado
    int64_t computeExpectedValue(size_t index) const {
        return (index + 1) * 10; // Misma lógica que la DB, lo incluí en la clase Client para "no revelar" el índice al servidor
    }
};

// CLASE SERVIDOR
class PIRServer {
private:
    CryptoContext<DCRTPoly> cryptoContext;
    std::vector<int64_t> database;
    Plaintext encryptedDatabase;
    
public:
    PIRServer(CryptoContext<DCRTPoly> cc, size_t dbSize) : cryptoContext(cc) {
        database.resize(dbSize);
        for (size_t i = 0; i < dbSize; i++) {
            database[i] = (i + 1) * 10;
        }
        encryptedDatabase = cryptoContext->MakePackedPlaintext(database);
    }
    
    Ciphertext<DCRTPoly> processQuery(const Ciphertext<DCRTPoly>& encryptedSelector) const {
        // 1. Multiplicar selector por la base de datos 
        auto masked = cryptoContext->EvalMult(encryptedSelector, encryptedDatabase);
        
        // 2. Sumar todos los elementos para obtener el seleccionado
        return cryptoContext->EvalSum(masked, database.size());
    }
    
    void displayDatabasePreview() const {
        std::cout << "[SERVIDOR] Base de datos (primeros 10 elementos): ";
        for (size_t i = 0; i < std::min<size_t>(10, database.size()); i++) {
            std::cout << database[i] << " ";
        }
        if (database.size() > 10) std::cout << "...";
        std::cout << std::endl;
    }
};

// PROGRAMA PRINCIPAL
int main() {
    size_t dbSize;
    std::cout << "Tamaño de la base de datos: ";
    std::cin >> dbSize;

    if (dbSize == 0) {
        std::cerr << "Error: El tamaño debe ser positivo" << std::endl;
        return 1;
    }

    // CLIENTE
    std::cout << "\n[CLIENTE] Inicializando..." << std::endl;
    PIRClient client;
    client.initialize();
    client.generateKeys();

    // SERVIDOR
    std::cout << "\n[SERVIDOR] Inicializando base de datos..." << std::endl;
    PIRServer server(client.getCryptoContext(), dbSize);
    server.displayDatabasePreview();

    // CONSULTA CLIENTE
    size_t queryIndex;
    std::cout << "\n[CLIENTE] Índice a consultar (0 - " << dbSize - 1 << "): ";
    std::cin >> queryIndex;
    
    if (queryIndex >= dbSize) {
        std::cerr << "Error: Índice fuera de rango" << std::endl;
        return 1;
    }

    std::cout << "[CLIENTE] Creando consulta cifrada..." << std::endl;
    auto encryptedQuery = client.createQuery(queryIndex, dbSize);

    // PROCESAMIENTO SERVIDOR
    std::cout << "\n[SERVIDOR] Procesando consulta..." << std::endl;
    auto encryptedResult = server.processQuery(encryptedQuery);

    // RESULTADO CLIENTE
    std::cout << "\n[CLIENTE] Descifrando resultado..." << std::endl;
    int64_t result = client.decryptResult(encryptedResult);
    int64_t expected = client.computeExpectedValue(queryIndex);

    // Resultados
    std::cout << "\nResultado de la consulta PIR:" << std::endl;
    std::cout << "Índice solicitado: " << queryIndex << std::endl;
    std::cout << "Valor recuperado: " << result << std::endl;
    std::cout << "Valor esperado: " << expected << std::endl;
    
    if (result == expected) {
        std::cout << "ÉXITO: Resultado correcto" << std::endl;
    } else {
        std::cerr << "ERROR: Resultado incorrecto (Diferencia: " 
                  << (expected - result) << ")" << std::endl;
    }

    std::cout << "\nUso de memoria: " << getMemoryUsage() << " KB" << std::endl;
    return 0;
}
