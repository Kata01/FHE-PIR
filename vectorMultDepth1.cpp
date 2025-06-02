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

int main() {
    size_t dbSize;
    std::cout << "Tamaño de la base de datos: ";
    std::cin >> dbSize;

    if (dbSize == 0) {
        std::cerr << "Error: tamaño inválido" << std::endl;
        return 1;
    }

    // Configurar parámetros de FHE
    CCParams<CryptoContextBGVRNS> params;
    params.SetMultiplicativeDepth(1); 
    params.SetPlaintextModulus(65537);
    params.SetRingDim(16384);
    params.SetSecurityLevel(HEStd_128_classic);

    auto start = std::chrono::high_resolution_clock::now();
    CryptoContext<DCRTPoly> cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    auto end = std::chrono::high_resolution_clock::now();
    std::cout << "Contexto generado en " << (end - start).count() / 1e9 << " segundos\n";

    // Generar claves
    start = std::chrono::high_resolution_clock::now();
    auto keys = cc->KeyGen();

    // Para EvalSum (rotaciones necesarias)
    std::vector<int32_t> rotIndices;
    for (size_t i = 1; i < dbSize; i <<= 1)
        rotIndices.push_back(static_cast<int32_t>(i));
    cc->EvalAtIndexKeyGen(keys.secretKey, rotIndices);
    end = std::chrono::high_resolution_clock::now();
    std::cout << "Llaves generadas en " << (end - start).count() / 1e9 << " segundos\n";

    // Crear base de datos en texto plano
    std::vector<int64_t> database(dbSize);
    for (size_t i = 0; i < dbSize; ++i)
        database[i] = static_cast<int64_t>((i + 1) * 10);

    Plaintext ptDatabase = cc->MakePackedPlaintext(database);

    // Mostrar primeros valores
    std::cout << "Base de datos: ";
    for (size_t i = 0; i < std::min(dbSize, size_t(10)); ++i)
        std::cout << database[i] << " ";
    std::cout << (dbSize > 10 ? "... " : "") << std::endl;

    // Preguntar índice
    size_t queryIndex;
    std::cout << "Índice a recuperar (0 - " << dbSize - 1 << "): ";
    std::cin >> queryIndex;

    if (queryIndex >= dbSize) {
        std::cerr << "Error: índice fuera de rango\n";
        return 1;
    }

    // Crear vector selector con un 1 en la posición a recuperar (cliente)
    std::vector<int64_t> selector(dbSize, 0);
    selector[queryIndex] = 1;
    Plaintext ptSelector = cc->MakePackedPlaintext(selector);
    auto encryptedSelector = cc->Encrypt(keys.publicKey, ptSelector);

    // PIR: EvalMult + EvalSum (Servidor)
    start = std::chrono::high_resolution_clock::now();
    auto encryptedProduct = cc->EvalMult(encryptedSelector, ptDatabase);
    auto encryptedResult = cc->EvalSum(encryptedProduct, dbSize);
    end = std::chrono::high_resolution_clock::now();
    std::cout << "Cálculo PIR completado en " << (end - start).count() / 1e9 << " segundos\n";

    // Desencriptar resultado (Cliente)
    start = std::chrono::high_resolution_clock::now();
    Plaintext decryptedResult;
    cc->Decrypt(keys.secretKey, encryptedResult, &decryptedResult);
    decryptedResult->SetLength(1);
    end = std::chrono::high_resolution_clock::now();
    std::cout << "Resultado desencriptado en " << (end - start).count() / 1e9 << " segundos\n";

    // Resultado
    int64_t recovered = decryptedResult->GetPackedValue()[0];
    std::cout << "\nResultado recuperado: " << recovered << std::endl;
    std::cout << "Valor real esperado: " << database[queryIndex] << std::endl;

    if (recovered == database[queryIndex])
        std::cout << "Coinciden\n";
    else
        std::cout << "ERROR: resultado incorrecto\n";

    std::cout << "\nUso de memoria: " << getMemoryUsage() << " KB\n";
    return 0;
}
