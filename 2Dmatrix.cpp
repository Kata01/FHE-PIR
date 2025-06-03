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

//  CLASE SERVIDOR 
class Server {
private:
    CryptoContext<DCRTPoly> cryptoContext;
    std::vector<std::vector<int64_t>> databaseMatrix;
    size_t rows, cols;

public:
    // Constructor de la matriz de la base de datos
    Server(int totalEntries, CryptoContext<DCRTPoly> cc) : cryptoContext(cc) {
        rows = static_cast<size_t>(std::sqrt(totalEntries));
        if (rows * rows < static_cast<size_t>(totalEntries)) rows++;
        cols = (static_cast<size_t>(totalEntries) + rows - 1) / rows;
    
        databaseMatrix.resize(rows, std::vector<int64_t>(cols, 0));
        
        int64_t value = 10;
        for (size_t i = 0; i < rows; ++i) {
            for (size_t j = 0; j < cols; ++j) {
                if (i * cols + j < static_cast<size_t>(totalEntries)) {
                    databaseMatrix[i][j] = value;
                    value += 10;
                }
            }
        }
    }

    // Procesar consulta PIR-FHE
    Ciphertext<DCRTPoly> processQuery(const Ciphertext<DCRTPoly>& encryptedRowSelector, 
                                    const Ciphertext<DCRTPoly>& encryptedColSelector) {
        // Convertir matriz a vector plano aplanando por filas
        std::vector<int64_t> flatMatrix;
        for (const auto& row : databaseMatrix) {
            flatMatrix.insert(flatMatrix.end(), row.begin(), row.end());
        }
        Plaintext ptMatrix = cryptoContext->MakePackedPlaintext(flatMatrix);

        // Multiplicar la matriz por ambos selectores
        auto maskedMatrix = cryptoContext->EvalMult(ptMatrix, encryptedRowSelector);
        maskedMatrix = cryptoContext->EvalMult(maskedMatrix, encryptedColSelector);

        // Sumar todos los elementos
        return cryptoContext->EvalSum(maskedMatrix, rows * cols);
    }

    // Mostrar la matriz
    void displayMatrix() const {
        if (rows <= 10 && cols <= 10) {
            std::cout << "\nMatriz en el servidor:" << std::endl;
            for (const auto& row : databaseMatrix) {
                for (const auto& entry : row) {
                    std::cout << entry << " ";
                }
                std::cout << std::endl;
            }
        }
    }

    size_t getRows() const { return rows; }
    size_t getCols() const { return cols; }
};

//  CLASE CLIENTE 
class Client {
private:
    CryptoContext<DCRTPoly> cryptoContext;
    KeyPair<DCRTPoly> keyPair;

public:
    // Constructor para configurar el contexto criptográfico
    Client() {
        CCParams<CryptoContextBGVRNS> parameters;
        parameters.SetMultiplicativeDepth(2);
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
        cryptoContext->EvalMultKeyGen(keyPair.secretKey);

        // Preparar rotaciones para EvalSum (tamaño máximo estimado)
        std::vector<int> rotationIndices;
        for (size_t i = 1; i < 16384; i <<= 1) {
            rotationIndices.push_back(static_cast<int>(i));
        }
        cryptoContext->EvalAtIndexKeyGen(keyPair.secretKey, rotationIndices);
    }

    // Crear consulta PIR
    std::pair<Ciphertext<DCRTPoly>, Ciphertext<DCRTPoly>> createQuery(size_t desiredRow, size_t desiredCol, 
                                                                    size_t rows, size_t cols) {
        // 1. Crear vector selector de fila
        std::vector<int64_t> rowSelector(rows * cols, 0);
        for (size_t j = 0; j < cols; ++j) {
            rowSelector[desiredRow * cols + j] = 1;
        }
        Plaintext ptRowSelector = cryptoContext->MakePackedPlaintext(rowSelector);
        auto encryptedRowSelector = cryptoContext->Encrypt(keyPair.publicKey, ptRowSelector);

        // 2. Crear vector selector de columna
        std::vector<int64_t> colSelector(rows * cols, 0);
        for (size_t i = 0; i < rows; ++i) {
            colSelector[i * cols + desiredCol] = 1;
        }
        Plaintext ptColSelector = cryptoContext->MakePackedPlaintext(colSelector);
        auto encryptedColSelector = cryptoContext->Encrypt(keyPair.publicKey, ptColSelector);

        return {encryptedRowSelector, encryptedColSelector};
    }

    // Descifrar resultado
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
    int totalEntries;
    std::cout << "Escribe el número total de entradas en la base de datos: ";
    std::cin >> totalEntries;
    
    if (totalEntries <= 0) {
        std::cerr << "Error: El número de entradas debe ser positivo." << std::endl;
        return 1;
    }

    // PARTE CLIENTE
    std::cout << "\n[CLIENTE] Configurando contexto criptográfico..." << std::endl;
    auto clientStart = std::chrono::high_resolution_clock::now();
    
    Client client;
    client.generateKeys();
    
    auto clientEnd = std::chrono::high_resolution_clock::now();
    std::cout << "[CLIENTE] Configuración completada en " 
              << std::chrono::duration<double>(clientEnd - clientStart).count() << " segundos" << std::endl;

    // PARTE SERVIDOR
    std::cout << "\n[SERVIDOR] Inicializando base de datos..." << std::endl;
    Server server(totalEntries, client.getCryptoContext());
    server.displayMatrix();
    std::cout << "[SERVIDOR] Base de datos creada con dimensiones " << server.getRows() 
              << "x" << server.getCols() << std::endl;

    // CONSULTA CLIENTE
    int entryIndex;
    do {
        std::cout << "\n[CLIENTE] Escribe el índice de la entrada a recuperar (0-" << totalEntries - 1 << "): ";
        std::cin >> entryIndex;
        if (entryIndex < 0 || entryIndex >= totalEntries) {
            std::cerr << "Error: Índice fuera de rango. Por favor intentalo de nuevo." << std::endl;
        }
    } while (entryIndex < 0 || entryIndex >= totalEntries);
    
    size_t desiredRow = static_cast<size_t>(entryIndex) / server.getCols();
    size_t desiredCol = static_cast<size_t>(entryIndex) % server.getCols();
    std::cout << "[CLIENTE] Recuperando entrada en la posición (" << desiredRow << ", " << desiredCol << ")" << std::endl;

    auto queryStart = std::chrono::high_resolution_clock::now();
    auto [encryptedRowSelector, encryptedColSelector] = client.createQuery(desiredRow, desiredCol, server.getRows(), server.getCols());
    auto queryEnd = std::chrono::high_resolution_clock::now();
    std::cout << "[CLIENTE] Consulta creada en " 
              << std::chrono::duration<double>(queryEnd - queryStart).count() << " segundos" << std::endl;

    // PROCESAMIENTO SERVIDOR
    std::cout << "\n[SERVIDOR] Procesando consulta PIR..." << std::endl;
    auto serverStart = std::chrono::high_resolution_clock::now();
    
    Ciphertext<DCRTPoly> encryptedResult = server.processQuery(encryptedRowSelector, encryptedColSelector);
    
    auto serverEnd = std::chrono::high_resolution_clock::now();
    std::cout << "[SERVIDOR] Consulta procesada en " 
              << std::chrono::duration<double>(serverEnd - serverStart).count() << " segundos" << std::endl;

    // RESULTADO CLIENTE
    std::cout << "\n[CLIENTE] Desencriptando resultado..." << std::endl;
    auto decryptStart = std::chrono::high_resolution_clock::now();
    
    int64_t result = client.decryptResult(encryptedResult);
    int64_t expectedValue = 10 + entryIndex * 10; // Valor esperado según la lógica de creación
    
    auto decryptEnd = std::chrono::high_resolution_clock::now();
    std::cout << "[CLIENTE] Resultado desencriptado en " 
              << std::chrono::duration<double>(decryptEnd - decryptStart).count() << " segundos" << std::endl;

    // Resultados
    std::cout << "\nResultado de la consulta PIR:" << std::endl;
    std::cout << "Índice solicitado: " << entryIndex << std::endl;
    std::cout << "Posición en matriz: (" << desiredRow << ", " << desiredCol << ")" << std::endl;
    std::cout << "Valor recuperado: " << result << std::endl;
    std::cout << "Valor esperado: " << expectedValue << std::endl;
    std::cout << (result == expectedValue ? "ÉXITO: Resultado correcto" : "ERROR: Resultado incorrecto") << std::endl;

    std::cout << "\nUso de memoria: " << getMemoryUsage() << " KB" << std::endl;

    return 0;
}
