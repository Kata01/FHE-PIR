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
        return pmc.WorkingSetSize / 1024; // Uso de memoria en KB
    }
    return 0;
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
    parameters.SetMultiplicativeDepth(2);
    parameters.SetPlaintextModulus(4293918721);
    parameters.SetRingDim(16384);
    parameters.SetSecurityLevel(HEStd_128_classic);

    // Definir contexto
    auto start = std::chrono::high_resolution_clock::now();
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    std::cout << "Contexto criptográfico configurado exitosamente. Tiempo: " << elapsed.count() << " segundos" << std::endl;

    // Generar claves (Cliente)
    start = std::chrono::high_resolution_clock::now();
    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "Par de claves generado exitosamente. Tiempo: " << elapsed.count() << " segundos" << std::endl;

    // Definir base de datos (Servidor)
    std::vector<int64_t> database(databaseSize);
    for (size_t i = 0; i < database.size(); i++) {
        database[i] = static_cast<int64_t>(i + 1) * 10; // Valores: 10, 20, 30, ...
    }

    std::cout << "Base de datos (primeras 10 entradas): ";
    for (size_t i = 0; i < std::min<size_t>(10, database.size()); i++) {
        std::cout << database[i] << " ";
    }
    std::cout << "... (total " << database.size() << " entradas)" << std::endl;

    // Cifra el índice de la entrada deseada (Cliente)
    size_t desiredIndex;
    std::cout << "Ingrese el índice a consultar (0 a " << database.size() - 1 << "): ";
    std::cin >> desiredIndex;

    if (desiredIndex >= database.size()) {
        std::cerr << "Error: Índice fuera de rango" << std::endl;
        return 1;
    }

    Plaintext ptIndex = cryptoContext->MakePackedPlaintext({static_cast<int64_t>(desiredIndex)});
    auto encryptedIndex = cryptoContext->Encrypt(keyPair.publicKey, ptIndex);

    std::cout << "Índice " << desiredIndex << " cifrado exitosamente" << std::endl;


    start = std::chrono::high_resolution_clock::now();

    // Inicialización del resultado como un cero cifrado(Servidor)
    auto encryptedResult = cryptoContext->Encrypt(keyPair.publicKey, cryptoContext->MakePackedPlaintext({0}));

    // Calcular producto entre el índice cifrado y la base de datos (Servidor)
    for (size_t i = 0; i < database.size(); i++) {
        std::vector<int64_t> selector(database.size(), 0);
        selector[i] = 1;
        Plaintext ptSelector = cryptoContext->MakePackedPlaintext(selector);
        auto encryptedSelector = cryptoContext->Encrypt(keyPair.publicKey, ptSelector);
        auto encryptedProduct = cryptoContext->EvalMult(encryptedIndex, encryptedSelector);
        auto encryptedScaled = cryptoContext->EvalMult(encryptedProduct, cryptoContext->MakePackedPlaintext({database[i]}));
        encryptedResult = cryptoContext->EvalAdd(encryptedResult, encryptedScaled);
    }

    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "Cálculo PIR completado en el servidor. Tiempo: " << elapsed.count() << " segundos" << std::endl;

    // Descifra el resultado (Cliente)
    start = std::chrono::high_resolution_clock::now();
    Plaintext decryptedResult;
    cryptoContext->Decrypt(keyPair.secretKey, encryptedResult, &decryptedResult);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "Descifrado completado. Tiempo: " << elapsed.count() << " segundos" << std::endl;

    std::cout << "Resultado descifrado: ";
    decryptedResult->SetLength(1);
    std::cout << decryptedResult->GetPackedValue()[0] << std::endl;

    size_t memoryUsage = getMemoryUsage();
    std::cout << "Uso de memoria: " << memoryUsage << " KB" << std::endl;

    return 0;
}
