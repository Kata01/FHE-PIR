#include <openfhe.h>
#include <iostream>
#include <vector>
#include <chrono>
#include <windows.h>
#include <psapi.h>

using namespace lbcrypto;

// Función para medir uso de memoria
size_t getMemoryUsage() {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize / 1024;
    }
    return 0;
}

// CLIENTE: Inicialización y generación de claves
CryptoContext<DCRTPoly> inicializarContexto() {
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetMultiplicativeDepth(2);
    parameters.SetPlaintextModulus(4293918721);
    parameters.SetRingDim(16384);
    parameters.SetSecurityLevel(HEStd_128_classic);
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    return cc;
}

// CLIENTE: Cifrar del índice deseado
Ciphertext<DCRTPoly> cifrarIndice(CryptoContext<DCRTPoly> cc, PublicKey<DCRTPoly> pk, size_t index) {
    Plaintext pt = cc->MakePackedPlaintext({ static_cast<int64_t>(index) });
    return cc->Encrypt(pk, pt);
}

// SERVIDOR: Procesamiento PIR-FHE
Ciphertext<DCRTPoly> ejecutarPIRFHE(CryptoContext<DCRTPoly> cc,
                                  const std::vector<int64_t>& db,
                                  Ciphertext<DCRTPoly> encryptedIndex,
                                  PublicKey<DCRTPoly> pk) {
    auto encryptedResult = cc->Encrypt(pk, cc->MakePackedPlaintext({ 0 }));
    for (size_t i = 0; i < db.size(); i++) {
        std::vector<int64_t> selector(db.size(), 0);
        selector[i] = 1;
        Plaintext ptSelector = cc->MakePackedPlaintext(selector);
        auto encryptedSelector = cc->Encrypt(pk, ptSelector);
        auto encryptedProduct = cc->EvalMult(encryptedIndex, encryptedSelector);
        auto encryptedScaled = cc->EvalMult(encryptedProduct, cc->MakePackedPlaintext({ db[i] }));
        encryptedResult = cc->EvalAdd(encryptedResult, encryptedScaled);
    }
    return encryptedResult;
}

// CLIENTE: Descifrar resultado
int64_t descifrarResultado(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ctxt, const PrivateKey<DCRTPoly>& sk) {
    Plaintext pt;
    cc->Decrypt(sk, ctxt, &pt);
    pt->SetLength(1);
    return pt->GetPackedValue()[0];
}

int main() {
    size_t dbSize;
    std::cout << "Escribe el tamaño de la base de datos: ";
    std::cin >> dbSize;

    if (dbSize == 0) {
        std::cerr << "Error: El tamaño debe ser positivo" << std::endl;
        return 1;
    }

    // CLIENTE: Inicializa contexto y claves
    auto start = std::chrono::high_resolution_clock::now();
    auto cc = inicializarContexto();
    auto end = std::chrono::high_resolution_clock::now();
    std::cout << "Contexto criptográfico creado. Tiempo: " << (end - start).count() / 1e9 << " s" << std::endl;

    start = std::chrono::high_resolution_clock::now();
    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);
    end = std::chrono::high_resolution_clock::now();
    std::cout << "Claves generadas. Tiempo: " << (end - start).count() / 1e9 << " s" << std::endl;

    // SERVIDOR: Crea base de datos
    std::vector<int64_t> db(dbSize);
    for (size_t i = 0; i < dbSize; i++) db[i] = (i + 1) * 10;

    std::cout << "Base de datos (primeros 10): ";
    for (size_t i = 0; i < std::min<size_t>(10, dbSize); i++) std::cout << db[i] << " ";
    std::cout << "...\n";

    // CLIENTE: Cifra índice
    size_t index;
    std::cout << "Índice a consultar (0 - " << dbSize - 1 << "): ";
    std::cin >> index;
    if (index >= dbSize) {
        std::cerr << "Índice fuera de rango" << std::endl;
        return 1;
    }
    auto encryptedIndex = cifrarIndice(cc, keyPair.publicKey, index);
    std::cout << "Índice cifrado correctamente.\n";

    // SERVIDOR: Cálculo PIR-FHE
    start = std::chrono::high_resolution_clock::now();
    auto encryptedResult = ejecutarPIRFHE(cc, db, encryptedIndex, keyPair.publicKey);
    end = std::chrono::high_resolution_clock::now();
    std::cout << "Servidor completó el cálculo PIR en " << (end - start).count() / 1e9 << " s\n";

    // CLIENTE: Descifra el resultado
    start = std::chrono::high_resolution_clock::now();
    int64_t resultado = descifrarResultado(cc, encryptedResult, keyPair.secretKey);
    end = std::chrono::high_resolution_clock::now();
    std::cout << "Cliente descifró el resultado en " << (end - start).count() / 1e9 << " s\n";
    std::cout << "Valor recuperado de la base de datos: " << resultado << "\n";

    std::cout << "Uso de memoria: " << getMemoryUsage() << " KB\n";
    return 0;
}
