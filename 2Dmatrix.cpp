//PIR usando matriz 2D

#include <openfhe.h>
#include <iostream>
#include <vector>
#include <chrono>
#include <windows.h>
#include <psapi.h>
#include <cmath>

using namespace lbcrypto;

size_t getMemoryUsage() {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize / 1024;
    }
    return 0; 
}

std::vector<std::vector<int64_t>> createMatrix(int totalEntries, int& rows, int& cols) {
    rows = static_cast<int>(std::sqrt(totalEntries));
    if (rows * rows < totalEntries) rows++;
    cols = (totalEntries + rows - 1) / rows;
    
    std::vector<std::vector<int64_t>> matrix(rows, std::vector<int64_t>(cols, 0));
    
    int64_t value = 10;
    for (int i = 0; i < rows; ++i) {
        for (int j = 0; j < cols; ++j) {
            if (i * cols + j < totalEntries) {
                matrix[i][j] = value;
                value += 10;
            }
        }
    }
    
    return matrix;
}

int main() {
    int totalEntries;
    std::cout << "Escribe el número total de entradas en la base de datos: ";
    std::cin >> totalEntries;
    
    if (totalEntries <= 0) {
        std::cerr << "Error: El número de entradas debe ser positivo." << std::endl;
        return 1;
    }

    // Crear y mostrar matriz del tamaño especificado
    int rows, cols;
    auto matrix = createMatrix(totalEntries, rows, cols);
    
    std::cout << "\nCreada " << rows << "x" << cols << " matriz con " 
              << totalEntries << " entradas" << std::endl;
    
    if (rows <= 10 && cols <= 10) {
        std::cout << "\nMatriz:" << std::endl;
        for (const auto& row : matrix) {
            for (const auto& entry : row) {
                std::cout << entry << " ";
            }
            std::cout << std::endl;
        }
    }

    // Preguntar la entrada
    int entryIndex;
    do {
        std::cout << "\nEscribe el índice de la entrada a recuperar (0-" << totalEntries - 1 << "): ";
        std::cin >> entryIndex;
        if (entryIndex < 0 || entryIndex >= totalEntries) {
            std::cerr << "Error: Índice fuera de rango. Por favor intentalo de nuevo." << std::endl;
        }
    } while (entryIndex < 0 || entryIndex >= totalEntries);
    
    int desiredRow = entryIndex / cols;
    int desiredCol = entryIndex % cols;
    std::cout << "Recuperando entrada en la posición (" << desiredRow << ", " << desiredCol << ")" << std::endl;

    // Parámetros
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetMultiplicativeDepth(4);
    parameters.SetPlaintextModulus(65537);
    parameters.SetRingDim(32768);
    parameters.SetSecurityLevel(HEStd_128_classic);
    
    // Contexto FHE
    auto start = std::chrono::high_resolution_clock::now();
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    std::cout << "\nContexto criptográfico configurado exitosamente. Tiempo: " << elapsed.count() << " seconds" << std::endl;

    // Generar llaves
    start = std::chrono::high_resolution_clock::now();
    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "Par de claves generado exitosamente. Tiempo: " << elapsed.count() << " seconds" << std::endl;

    // Encriptación del vector selector
    start = std::chrono::high_resolution_clock::now();
    
    // Vector fila
    std::vector<int64_t> rowSelection(rows, 0);
    rowSelection[desiredRow] = 1;
    Plaintext ptRow = cryptoContext->MakePackedPlaintext(rowSelection);
    
    // Vector columna
    std::vector<int64_t> colSelection(cols, 0);
    colSelection[desiredCol] = 1;
    Plaintext ptCol = cryptoContext->MakePackedPlaintext(colSelection);
    
    auto encryptedRow = cryptoContext->Encrypt(keyPair.publicKey, ptRow);
    auto encryptedCol = cryptoContext->Encrypt(keyPair.publicKey, ptCol);
    
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "Vectores de selección encriptados exitosamente. Tiempo: " << elapsed.count() << " segundos" << std::endl;

    // Computación PIR (Servidor)
    start = std::chrono::high_resolution_clock::now();
    auto encryptedResult = cryptoContext->Encrypt(keyPair.publicKey, cryptoContext->MakePackedPlaintext({0}));

    for (size_t i = 0; i < matrix.size(); i++) {
        std::vector<int64_t> currentRowSelector(rows, 0);
        currentRowSelector[i] = 1;
        Plaintext ptCurrentRow = cryptoContext->MakePackedPlaintext(currentRowSelector);
        auto encryptedCurrentRow = cryptoContext->Encrypt(keyPair.publicKey, ptCurrentRow);
        
        auto encryptedRowMatch = cryptoContext->EvalMult(encryptedRow, encryptedCurrentRow);

        for (size_t j = 0; j < matrix[i].size(); j++) {
            std::vector<int64_t> currentColSelector(cols, 0);
            currentColSelector[j] = 1;
            Plaintext ptCurrentCol = cryptoContext->MakePackedPlaintext(currentColSelector);
            auto encryptedCurrentCol = cryptoContext->Encrypt(keyPair.publicKey, ptCurrentCol);
            
            auto encryptedColMatch = cryptoContext->EvalMult(encryptedCol, encryptedCurrentCol);
            
            auto encryptedPositionMatch = cryptoContext->EvalMult(encryptedRowMatch, encryptedColMatch);
            
            auto encryptedValue = cryptoContext->EvalMult(
                encryptedPositionMatch,
                cryptoContext->MakePackedPlaintext({matrix[i][j]}));
            
            encryptedResult = cryptoContext->EvalAdd(encryptedResult, encryptedValue);
        }
    }
    
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "Cálculo PIR completado. Tiempo: " << elapsed.count() << " segundos" << std::endl;

    // Desencriptación de resultado (Cliente)
    start = std::chrono::high_resolution_clock::now();
    Plaintext decryptedResult;
    cryptoContext->Decrypt(keyPair.secretKey, encryptedResult, &decryptedResult);
    decryptedResult->SetLength(1);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "Decryption completed! Time: " << elapsed.count() << " segundos" << std::endl;

    // Resultados
    std::cout << "\nResultado consulta:" << std::endl;
    std::cout << "Entrada obtenida #" << entryIndex << ": " << decryptedResult->GetPackedValue()[0] << std::endl;
    std::cout << "Valor real en la base de datos: " << matrix[desiredRow][desiredCol] << std::endl;

    if (decryptedResult->GetPackedValue()[0] == matrix[desiredRow][desiredCol]) {
        std::cout << "El resultado coincide con el valor real" << std::endl;
    } else {
        std::cout << "ERROR: El resultado no coincide con el valor" << std::endl;
    }

    // Measure memory usage
    size_t memoryUsage = getMemoryUsage();
    std::cout << "\nUso de memoria: " << memoryUsage << " KB" << std::endl;

    return 0;
}
