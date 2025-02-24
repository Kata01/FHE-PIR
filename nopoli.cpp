// PIR using an array, without multidimensional matrix nor polynomial interpolation

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

int main() {
    // Define parameters
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetMultiplicativeDepth(2); 
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
    std::vector<int64_t> database(100); 
    for (size_t i = 0; i < database.size(); i++) {
        database[i] = static_cast<int64_t>(i + 1) * 10; // Values: 10, 20, 30, ...
    }

    std::cout << "Database (first 10 entries): ";
    for (size_t i = 0; i < 10; i++) {
        std::cout << database[i] << " ";
    }
    std::cout << "... (total " << database.size() << " entries)" << std::endl;

    // Client encrypts index of desired entry
    size_t desiredIndex = 42; 
    Plaintext ptIndex = cryptoContext->MakePackedPlaintext({static_cast<int64_t>(desiredIndex)});
    auto encryptedIndex = cryptoContext->Encrypt(keyPair.publicKey, ptIndex);

    std::cout << "Index " << desiredIndex << " encrypted successfully!" << std::endl;

    // Server performs PIR computation
    start = std::chrono::high_resolution_clock::now();

    // Initialize the result as an encrypted zero
    auto encryptedResult = cryptoContext->Encrypt(keyPair.publicKey, cryptoContext->MakePackedPlaintext({0}));

    // Compute dot product between the encrypted index and the database
    for (size_t i = 0; i < database.size(); i++) {
        // Vector with 1 at the desired index and 0 elsewhere
        std::vector<int64_t> selector(database.size(), 0);
        selector[i] = 1;
        Plaintext ptSelector = cryptoContext->MakePackedPlaintext(selector);

        // Encrypt selector vector
        auto encryptedSelector = cryptoContext->Encrypt(keyPair.publicKey, ptSelector);

        // Multiply the encrypted index with the selector
        auto encryptedProduct = cryptoContext->EvalMult(encryptedIndex, encryptedSelector);

        // Multiply product with the database entry
        auto encryptedScaled = cryptoContext->EvalMult(encryptedProduct, cryptoContext->MakePackedPlaintext({database[i]}));

        // Add the result to the accumulated sum
        encryptedResult = cryptoContext->EvalAdd(encryptedResult, encryptedScaled);
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
    decryptedResult->SetLength(1); // Ensure length matches the expected result
    std::cout << decryptedResult->GetPackedValue()[0] << std::endl;

    // Measure memory usage
    size_t memoryUsage = getMemoryUsage();
    std::cout << "Memory usage: " << memoryUsage << " KB" << std::endl;

    return 0;
}
