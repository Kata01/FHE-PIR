//PIR using 2D MATRIX

#include <openfhe.h>
#include <iostream>
#include <vector>
#include <chrono> // For timing
#include <windows.h> // For memory usage (Windows)
#include <psapi.h> // For memory usage (Windows)

using namespace lbcrypto;

// Function to get memory usage (Windows)
size_t getMemoryUsage() {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize / 1024; // Memory usage in KB
    }
    return 0; 
}

int main() {
    // Define parameters
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetMultiplicativeDepth(3); 
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

    // Define matrix (server-side)
    std::vector<std::vector<int64_t>> matrix = {
        {10, 20, 30, 40, 50},
        {60, 70, 80, 90, 100},
        {110, 120, 130, 140, 150},
        {160, 170, 180, 190, 200},
        {210, 220, 230, 240, 250}
    };
    std::cout << "Matrix:" << std::endl;
    for (const auto& row : matrix) {
        for (const auto& entry : row) {
            std::cout << entry << " ";
        }
        std::cout << std::endl;
    }

    // Client encrypts the row and column indices
    int64_t desiredRow = 2; // Row index (0-based)
    int64_t desiredCol = 3; // Column index (0-based)
    start = std::chrono::high_resolution_clock::now();
    Plaintext ptRow = cryptoContext->MakePackedPlaintext({desiredRow});
    Plaintext ptCol = cryptoContext->MakePackedPlaintext({desiredCol});
    auto encryptedRow = cryptoContext->Encrypt(keyPair.publicKey, ptRow);
    auto encryptedCol = cryptoContext->Encrypt(keyPair.publicKey, ptCol);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "Row and column indices encrypted successfully! Time: " << elapsed.count() << " seconds" << std::endl;

    // Server performs PIR computation
    start = std::chrono::high_resolution_clock::now();
    auto encryptedResult = cryptoContext->Encrypt(keyPair.publicKey, cryptoContext->MakePackedPlaintext({0}));

    for (size_t i = 0; i < matrix.size(); i++) {
        std::vector<int64_t> rowSelector(matrix.size(), 0);
        rowSelector[i] = 1;
        Plaintext ptRowSelector = cryptoContext->MakePackedPlaintext(rowSelector);
        auto encryptedRowSelector = cryptoContext->Encrypt(keyPair.publicKey, ptRowSelector);
        auto encryptedRowProduct = cryptoContext->EvalMult(encryptedRow, encryptedRowSelector);

        for (size_t j = 0; j < matrix[i].size(); j++) {
            std::vector<int64_t> colSelector(matrix[i].size(), 0);
            colSelector[j] = 1;
            Plaintext ptColSelector = cryptoContext->MakePackedPlaintext(colSelector);
            auto encryptedColSelector = cryptoContext->Encrypt(keyPair.publicKey, ptColSelector);
            auto encryptedColProduct = cryptoContext->EvalMult(encryptedCol, encryptedColSelector);
            auto encryptedProduct = cryptoContext->EvalMult(encryptedRowProduct, encryptedColProduct);
            auto encryptedScaled = cryptoContext->EvalMult(encryptedProduct, cryptoContext->MakePackedPlaintext({matrix[i][j]}));
            encryptedResult = cryptoContext->EvalAdd(encryptedResult, encryptedScaled);
        }
    }
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "PIR computation completed on the server! Time: " << elapsed.count() << " seconds" << std::endl;

    // Client decrypts result
    start = std::chrono::high_resolution_clock::now();
    Plaintext decryptedResult;
    cryptoContext->Decrypt(keyPair.secretKey, encryptedResult, &decryptedResult);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "Decryption completed! Time: " << elapsed.count() << " seconds" << std::endl;

    // Output result
    std::cout << "Decrypted result: ";
    decryptedResult->SetLength(1); // Ensure the length matches the expected result
    std::cout << decryptedResult->GetPackedValue()[0] << std::endl;

    // Measure memory usage
    size_t memoryUsage = getMemoryUsage();
    std::cout << "Memory usage: " << memoryUsage << " KB" << std::endl;

    return 0;
}
