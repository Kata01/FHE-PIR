//PIR using Polynomial Interpolation

#include <openfhe.h>
#include <iostream>
#include <vector>
#include <chrono> // For timing
#include <windows.h> // For memory usage (Windows)
#include <psapi.h> // For memory usage (Windows)

using namespace lbcrypto;

// Function to get memory usage
size_t getMemoryUsage() {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize / 1024; // Memory usage in KB
    }
    return 0; 
}

// Function to compute Lagrange coefficients
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
    // Define parameters
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetMultiplicativeDepth(1); 
    parameters.SetPlaintextModulus(4293918721); 
    parameters.SetRingDim(16384); 
    parameters.SetSecurityLevel(HEStd_128_classic);
    auto start = std::chrono::high_resolution_clock::now(); // Start timer
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    auto end = std::chrono::high_resolution_clock::now(); // End timer
    std::chrono::duration<double> elapsed = end - start;
    std::cout << "Crypto context set up successfully! Time: " << elapsed.count() << " seconds" << std::endl;

    // Generate keys
    start = std::chrono::high_resolution_clock::now();
    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "Key pair generated successfully! Time: " << elapsed.count() << " seconds" << std::endl;

    // Define the database (server-side)
    std::vector<int64_t> database(100); // Database with 100 entries
    for (size_t i = 0; i < database.size(); i++) {
        database[i] = static_cast<int64_t>(i + 1) * 10; // Values: 10, 20, 30, ..., 1000
    }
    std::vector<int64_t> indices(database.size());
    for (size_t i = 0; i < indices.size(); i++) {
        indices[i] = static_cast<int64_t>(i); // Indices: 0, 1, 2, ..., N-1
    }

    std::cout << "Database: ";
    for (const auto& entry : database) {
        std::cout << entry << " ";
    }
    std::cout << std::endl;

    // Client encrypts index of desired entry
    size_t desiredIndex = 42; 
    Plaintext ptIndex = cryptoContext->MakePackedPlaintext({static_cast<int64_t>(desiredIndex)});
    auto encryptedIndex = cryptoContext->Encrypt(keyPair.publicKey, ptIndex);

    std::cout << "Index " << desiredIndex << " encrypted successfully!" << std::endl;

    // Server performs polynomial interpolation
    start = std::chrono::high_resolution_clock::now();

    // Compute Lagrange coefficients
    std::vector<int64_t> lagrangeCoefficients = computeLagrangeCoefficients(indices, desiredIndex);

    // Evaluate the polynomial homomorphically
    auto encryptedResult = cryptoContext->Encrypt(keyPair.publicKey, cryptoContext->MakePackedPlaintext({0}));
    for (size_t i = 0; i < database.size(); i++) {
        // Compute the term: coefficient * database[i]
        Plaintext ptCoefficient = cryptoContext->MakePackedPlaintext({lagrangeCoefficients[i]});
        auto encryptedCoefficient = cryptoContext->Encrypt(keyPair.publicKey, ptCoefficient);
        auto encryptedTerm = cryptoContext->EvalMult(encryptedCoefficient, cryptoContext->MakePackedPlaintext({database[i]}));

        // Add the term to the result
        encryptedResult = cryptoContext->EvalAdd(encryptedResult, encryptedTerm);
    }

    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "Polynomial interpolation completed on the server! Time: " << elapsed.count() << " seconds" << std::endl;

    // Client decrypts result
    start = std::chrono::high_resolution_clock::now();
    Plaintext decryptedResult;
    cryptoContext->Decrypt(keyPair.secretKey, encryptedResult, &decryptedResult);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "Decryption completed! Time: " << elapsed.count() << " seconds" << std::endl;

    // Output result
    std::cout << "Decrypted result: ";
    decryptedResult->SetLength(1); // Ensure length matches the expected result
    std::cout << decryptedResult->GetPackedValue()[0] << std::endl;

    // Measure memory usage
    size_t memoryUsage = getMemoryUsage();
    std::cout << "Memory usage: " << memoryUsage << " KB" << std::endl;

    return 0;
}
