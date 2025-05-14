#include <openfhe.h>
#include <iostream>
#include <vector>
#include <chrono>
#include <windows.h>
#include <psapi.h>

using namespace lbcrypto;

// Función para obtener el uso de memoria
size_t getMemoryUsage() {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize / 1024; 
    }
    return 0;
}

// Función para calcular coeficientes de Lagrange
std::vector<int64_t> computeLagrangeCoefficients(const std::vector<int64_t>& x, size_t index) {
    size_t n = x.size();
    std::vector<int64_t> coefficients(n, 1);
    for (size_t i = 0; i < n; i++) {
        if (i == index) continue;
        for (size_t j = 0; j < n; j++) {
            if (j == index || j == i) continue;
            coefficients[j] *= (x[index] - x[i]) / (x[j] - x[i]);
        }
    }
    return coefficients;
}

int main() {
    size_t databaseSize;
    std::cout << "Escribe el tamaño de la base de datos: ";
    std::cin >> databaseSize;

    if (databaseSize <= 0) {
        std::cerr << "Error: El tamaño de la base de datos debe ser positivo" << std::endl;
        return 1;
    }

    // Definir parámetros
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetMultiplicativeDepth(1);
    parameters.SetPlaintextModulus(4293918721);
    parameters.SetRingDim(16384);
    parameters.SetSecurityLevel(HEStd_128_classic);

    auto start = std::chrono::high_resolution_clock::now();
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    std::cout << "Contexto criptográfico configurado exitosamente. Tiempo: " << elapsed.count() << " segundos" << std::endl;

    // Generar claves
    start = std::chrono::high_resolution_clock::now();
    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "Par de claves generado exitosamente. Tiempo: " << elapsed.count() << " segundos" << std::endl;

    // Definir la base de datos (servidor)
    std::vector<int64_t> database(databaseSize);
    for (size_t i = 0; i < database.size(); i++) {
        database[i] = static_cast<int64_t>(i + 1) * 10; // Valores: 10, 20, 30, ..., 10*N
    }

    std::vector<int64_t> indices(database.size());
    for (size_t i = 0; i < indices.size(); i++) {
        indices[i] = static_cast<int64_t>(i); // Índices: 0, 1, 2, ..., N-1
    }

    std::cout << "Base de datos (primeras 10 entradas): ";
    for (size_t i = 0; i < std::min<size_t>(10, database.size()); i++) {
        std::cout << database[i] << " ";
    }
    std::cout << std::endl;

    // Cifrar el índice de la entrada deseada (Cliente)
    size_t desiredIndex;
    std::cout << "Escribe el índice a consultar (0 a " << database.size() - 1 << "): ";
    std::cin >> desiredIndex;

    if (desiredIndex >= database.size()) {
        std::cerr << "Error: Índice fuera de rango" << std::endl;
        return 1;
    }

    Plaintext ptIndex = cryptoContext->MakePackedPlaintext({static_cast<int64_t>(desiredIndex)});
    auto encryptedIndex = cryptoContext->Encrypt(keyPair.publicKey, ptIndex);

    std::cout << "Índice " << desiredIndex << " cifrado exitosamente" << std::endl;

    start = std::chrono::high_resolution_clock::now();

    // Calcular coeficientes de Lagrange (servidor)
    std::vector<int64_t> lagrangeCoefficients = computeLagrangeCoefficients(indices, desiredIndex);

    // Evaluar el polinomio homomórficamente (servidor)
    auto encryptedResult = cryptoContext->Encrypt(keyPair.publicKey, cryptoContext->MakePackedPlaintext({0}));
    for (size_t i = 0; i < database.size(); i++) {
        Plaintext ptCoefficient = cryptoContext->MakePackedPlaintext({lagrangeCoefficients[i]});
        auto encryptedCoefficient = cryptoContext->Encrypt(keyPair.publicKey, ptCoefficient);
        auto encryptedTerm = cryptoContext->EvalMult(encryptedCoefficient, cryptoContext->MakePackedPlaintext({database[i]}));
        encryptedResult = cryptoContext->EvalAdd(encryptedResult, encryptedTerm);
    }

    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "Interpolación polinomial completada en el servidor Tiempo: " << elapsed.count() << " segundos" << std::endl;

    // Descifrar el resultado (Cliente)
    start = std::chrono::high_resolution_clock::now();
    Plaintext decryptedResult;
    cryptoContext->Decrypt(keyPair.secretKey, encryptedResult, &decryptedResult);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "Descifrado completado Tiempo: " << elapsed.count() << " segundos" << std::endl;

    std::cout << "Resultado descifrado: ";
    decryptedResult->SetLength(1);
    std::cout << decryptedResult->GetPackedValue()[0] << std::endl;

    size_t memoryUsage = getMemoryUsage();
    std::cout << "Uso de memoria: " << memoryUsage << " KB" << std::endl;

    return 0;
}
