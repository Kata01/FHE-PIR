#include <openfhe.h>
#include <iostream>
#include <vector>
#include <chrono>
#include <windows.h>
#include <psapi.h>
#include <cmath>

using namespace lbcrypto;

// Función para obtener uso de memoria
size_t getMemoryUsage() {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize / 1024;
    }
    return 0;
}

// CLASE SERVIDOR
class Server {
private:
    CryptoContext<DCRTPoly> cryptoContext;
    std::vector<int64_t> database;
    Plaintext encryptedDatabase;

public:
    // Constructor de la BD
    Server(size_t dbSize, CryptoContext<DCRTPoly> cc) : cryptoContext(cc) {
        // Crear base de datos de ejemplo
        database.resize(dbSize);
        for (size_t i = 0; i < dbSize; ++i) {
            database[i] = static_cast<int64_t>((i + 1) * 10);
        }
        
        // Pre-encriptar la base de datos
        encryptedDatabase = cryptoContext->MakePackedPlaintext(database);
    }

    // Procesar consulta PIR
    Ciphertext<DCRTPoly> processQuery(const Ciphertext<DCRTPoly>& encryptedSelector) {
        // 1. Multiplicar el selector por la base de datos
        auto encryptedProduct = cryptoContext->EvalMult(encryptedSelector, encryptedDatabase);
        
        // 2. Sumar todos los elementos
        return cryptoContext->EvalSum(encryptedProduct, database.size());
    }

    // Mostrar parte de la base de datos (para depuración)
    void displayDatabasePreview() const {
        std::cout << "[SERVIDOR] Base de datos (primeros valores): ";
        for (size_t i = 0; i < std::min(database.size(), size_t(10)); ++i) {
            std::cout << database[i] << " ";
        }
        if (database.size() > 10) std::cout << "...";
        std::cout << std::endl;
    }

    // Para verificación del resultado
    int64_t getExpectedValue(size_t index) const {
        return database[index];
    }
};

// CLASE CLIENTE
class Client {
private:
    CryptoContext<DCRTPoly> cryptoContext;
    KeyPair<DCRTPoly> keyPair;

public:
    // Configución del contexto criptográfico
    Client() {
        CCParams<CryptoContextBGVRNS> parameters;
        parameters.SetMultiplicativeDepth(1);
        parameters.SetPlaintextModulus(4293918721);
        parameters.SetRingDim(262144);
        parameters.SetSecurityLevel(HEStd_128_classic);
        
        cryptoContext = GenCryptoContext(parameters);
        cryptoContext->Enable(PKE);
        cryptoContext->Enable(KEYSWITCH);
        cryptoContext->Enable(LEVELEDSHE);
        cryptoContext->Enable(ADVANCEDSHE);
    }

    // Generar claves
    void generateKeys() {
        keyPair = cryptoContext->KeyGen();
        
        // // Generar claves de rotación para EvalSum (tamaño máximo estimado)
        std::vector<int32_t> rotationIndices;
        for (size_t i = 1; i < 16384; i <<= 1) {
            rotationIndices.push_back(static_cast<int32_t>(i));
        }
        cryptoContext->EvalAtIndexKeyGen(keyPair.secretKey, rotationIndices);
    }

    // Crear vector selector
    Ciphertext<DCRTPoly> createQuery(size_t queryIndex, size_t dbSize) {
        if (queryIndex >= dbSize) {
            throw std::out_of_range("Índice fuera de rango");
        }

        std::vector<int64_t> selector(dbSize, 0);
        selector[queryIndex] = 1;
        
        Plaintext ptSelector = cryptoContext->MakePackedPlaintext(selector);
        return cryptoContext->Encrypt(keyPair.publicKey, ptSelector);
    }

    // Desencriptar resultado
    int64_t decryptResult(const Ciphertext<DCRTPoly>& encryptedResult) {
        Plaintext decryptedResult;
        cryptoContext->Decrypt(keyPair.secretKey, encryptedResult, &decryptedResult);
        decryptedResult->SetLength(1);
        return decryptedResult->GetPackedValue()[0];
    }

    CryptoContext<DCRTPoly> getCryptoContext() const { return cryptoContext; }
    PublicKey<DCRTPoly> getPublicKey() const { return keyPair.publicKey; }
};

// PROGRAMA PRINCIPAL
int main() {

    size_t dbSize;
    std::cout << "Tamaño de la base de datos: ";
    std::cin >> dbSize;

    if (dbSize == 0) {
        std::cerr << "Error: tamaño inválido" << std::endl;
        return 1;
    }

    // CLIENTE
    std::cout << "\n[CLIENTE] Configurando contexto criptográfico..." << std::endl;
    auto clientStart = std::chrono::high_resolution_clock::now();
    
    Client client;
    client.generateKeys();
    
    auto clientEnd = std::chrono::high_resolution_clock::now();
    std::cout << "[CLIENTE] Configuración completada en " 
              << std::chrono::duration<double>(clientEnd - clientStart).count() << " segundos" << std::endl;

    // SERVIDOR
    std::cout << "\n[SERVIDOR] Inicializando base de datos..." << std::endl;
    Server server(dbSize, client.getCryptoContext());
    server.displayDatabasePreview();

    // CONSULTA CLIENTE
    size_t queryIndex;
    std::cout << "\n[CLIENTE] Índice a recuperar (0 - " << dbSize - 1 << "): ";
    std::cin >> queryIndex;

    if (queryIndex >= dbSize) {
        std::cerr << "Error: índice fuera de rango\n";
        return 1;
    }


    auto queryStart = std::chrono::high_resolution_clock::now();
    Ciphertext<DCRTPoly> encryptedSelector = client.createQuery(queryIndex, dbSize);
    auto queryEnd = std::chrono::high_resolution_clock::now();
    std::cout << "[CLIENTE] Consulta creada en " 
              << std::chrono::duration<double>(queryEnd - queryStart).count() << " segundos" << std::endl;

    // PROCESAMIENTO SERVIDOR
    std::cout << "\n[SERVIDOR] Procesando consulta PIR..." << std::endl;
    auto serverStart = std::chrono::high_resolution_clock::now();
    
    Ciphertext<DCRTPoly> encryptedResult = server.processQuery(encryptedSelector);
    
    auto serverEnd = std::chrono::high_resolution_clock::now();
    std::cout << "[SERVIDOR] Consulta procesada en " 
              << std::chrono::duration<double>(serverEnd - serverStart).count() << " segundos" << std::endl;

    // RESULTADO CLIENTE
    std::cout << "\n[CLIENTE] Desencriptando resultado..." << std::endl;
    auto decryptStart = std::chrono::high_resolution_clock::now();
    
    int64_t recovered = client.decryptResult(encryptedResult);
    int64_t expected = server.getExpectedValue(queryIndex);
    
    auto decryptEnd = std::chrono::high_resolution_clock::now();
    std::cout << "[CLIENTE] Resultado desencriptado en " 
              << std::chrono::duration<double>(decryptEnd - decryptStart).count() << " segundos" << std::endl;

    // Mostrar resultados
    std::cout << "\nResultado de la consulta PIR:" << std::endl;
    std::cout << "Índice solicitado: " << queryIndex << std::endl;
    std::cout << "Valor recuperado: " << recovered << std::endl;
    std::cout << "Valor esperado: " << expected << std::endl;
    std::cout << (recovered == expected ? "ÉXITO: Resultado correcto" : "ERROR: Resultado incorrecto") << std::endl;

    std::cout << "\nUso de memoria: " << getMemoryUsage() << " KB" << std::endl;

    return 0;
}
