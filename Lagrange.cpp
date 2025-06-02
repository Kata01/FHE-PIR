// Lagrange

#include <openfhe.h>
#include <iostream>
#include <vector>
#include <chrono>
#include <stdexcept>
#include <algorithm>
#include <windows.h>
#include <psapi.h>
#include <complex>
#include <cmath>
#include <iomanip>
#include <sstream>

using namespace lbcrypto;

size_t getMemoryUsage() {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize / 1024; 
    }
    return 0;
}

// Configuración del contexto CKKS para datos continuos (Admite hasta 24 horas)
CryptoContext<DCRTPoly> configureContext() {
    CCParams<CryptoContextCKKSRNS> parameters;
    
    parameters.SetMultiplicativeDepth(24);
    parameters.SetScalingModSize(50);
    parameters.SetRingDim(262144);
    parameters.SetBatchSize(64);
    parameters.SetScalingTechnique(FLEXIBLEAUTO);
    
    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetNumLargeDigits(3);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    
    return cryptoContext;
}

// Función para convertir HH:MM:SS a horas decimales
double timeStringToHours(const std::string& timeStr) {
    int hours, minutes, seconds;
    char colon;
    std::istringstream iss(timeStr);
    
    if (!(iss >> hours >> colon >> minutes >> colon >> seconds) || colon != ':') {
        throw std::runtime_error("Formato de tiempo inválido. Use HH:MM:SS");
    }
    
    if (hours < 0 ||hours > 23 || minutes < 0 || minutes > 59 || seconds < 0 || seconds > 59) {
        throw std::runtime_error("Tiempo fuera de rango. Use HH::MM:00-59:SS:00-59");
    }
    
    return hours + (minutes / 60.0) + (seconds / 3600.0);
}

// Función para convertir horas decimales a HH:MM:SS
std::string hoursToTimeString(double hours) {
    int totalSeconds = static_cast<int>(hours * 3600);
    int h = totalSeconds / 3600;
    int m = (totalSeconds % 3600) / 60;
    int s = totalSeconds % 60;
    
    std::ostringstream oss;
    oss << std::setfill('0') << std::setw(2) << h << ":"
        << std::setfill('0') << std::setw(2) << m << ":"
        << std::setfill('0') << std::setw(2) << s;
    return oss.str();
}

// Función de interpolación de Lagrande homomórfica
Ciphertext<DCRTPoly> homomorphicLagrangeInterpolation(
    CryptoContext<DCRTPoly> cryptoContext,
    const std::vector<double>& temperatures,
    const std::vector<double>& timestamps,
    const Ciphertext<DCRTPoly>& encryptedTimestamp,
    const PublicKey<DCRTPoly>& publicKey) {
    
    if (temperatures.size() != timestamps.size()) {
        throw std::runtime_error("Temperatures and timestamps must have the same size");
    }

    // Precalcular denominadores
    std::vector<double> denominators(timestamps.size(), 1.0);
    for (size_t j = 0; j < timestamps.size(); j++) {
        for (size_t i = 0; i < timestamps.size(); i++) {
            if (i != j) denominators[j] *= (timestamps[j] - timestamps[i]);
        }
    }

    auto encryptedResult = cryptoContext->Encrypt(publicKey, 
        cryptoContext->MakeCKKSPackedPlaintext(std::vector<double>{0.0}));
    
    for (size_t j = 0; j < temperatures.size(); j++) {
        try {
            // Calcular numerador
            auto numerator = cryptoContext->Encrypt(publicKey, 
                cryptoContext->MakeCKKSPackedPlaintext(std::vector<double>{1.0}));
            
            for (size_t i = 0; i < timestamps.size(); i++) {
                if (i == j) continue;
                auto term = cryptoContext->EvalSub(
                    encryptedTimestamp,
                    cryptoContext->MakeCKKSPackedPlaintext(std::vector<double>{timestamps[i]})
                );
                numerator = cryptoContext->EvalMultAndRelinearize(numerator, term);
            }
            
            numerator = cryptoContext->Rescale(numerator);
            
            // Calcular coeficiente
            double coeff = temperatures[j] / denominators[j];
            auto plainCoeff = cryptoContext->MakeCKKSPackedPlaintext(std::vector<double>{coeff});
            
            // Multiplicar y sumar
            auto term = cryptoContext->EvalMult(numerator, plainCoeff);
            term = cryptoContext->Rescale(term);
            encryptedResult = cryptoContext->EvalAdd(encryptedResult, term);
            
        } catch (const std::exception& e) {
            std::cerr << "Error en timestamp " << timestamps[j] << ": " << e.what() << std::endl;
            throw;
        }
    }
    
    return encryptedResult;
}

int main() {
    std::cout << "Uso de memoria inicial: " << getMemoryUsage() << " KB" << std::endl;

    // Configurar contexto criptográfico CKKS
    auto start = std::chrono::high_resolution_clock::now();
    CryptoContext<DCRTPoly> cryptoContext = configureContext();
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    std::cout << "Contexto criptográfico configurado. Tiempo: " << elapsed.count() 
              << " segundos. Memoria: " << getMemoryUsage() << " KB" << std::endl;

    // Generar claves (Cliente)
    start = std::chrono::high_resolution_clock::now();
    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "Claves generadas. Tiempo: " << elapsed.count() 
              << " segundos. Memoria: " << getMemoryUsage() << " KB" << std::endl;

    // Crear base de datos de temperaturas con timestamps en formato HH:MM:SS (servidor)
    size_t dataPoints;
    std::cout << "Número de puntos de datos de temperatura (Entre 1 y 24): ";
    std::cin >> dataPoints;
    
    std::vector<double> temperatures(dataPoints);
    std::vector<double> timestamps(dataPoints);
    std::vector<std::string> timestampStrings(dataPoints);
    
    // Generar datos de ejemplo (cada punto representa 1 hora)
    for (size_t i = 0; i < dataPoints; i++) {
        int totalSeconds = i * 3600;
        int h = totalSeconds / 3600;
        int m = (totalSeconds % 3600) / 60;
        int s = totalSeconds % 60;
        
        std::ostringstream oss;
        oss << std::setfill('0') << std::setw(2) << h << ":"
            << std::setfill('0') << std::setw(2) << m << ":"
            << std::setfill('0') << std::setw(2) << s;
        
        timestampStrings[i] = oss.str();
        timestamps[i] = h + (m / 60.0) + (s / 3600.0); // Convertir a horas decimales
        temperatures[i] = 20.0 + 10.0 * sin(i * 0.5);   // Temperatura fluctuante
    }

    // Mostrar dataset (servidor)
    std::cout << "\nDatos de temperatura (primeros 10 puntos):" << std::endl;
    std::cout << "Timestamp\tTemperatura (C)" << std::endl;
    for (size_t i = 0; i < temperatures.size(); i++) {
        std::cout << timestampStrings[i] << "\t" << temperatures[i] << std::endl;
    }

    // Solicitar timestamp en formato HH:MM:SS (servidor)
    std::string queryTimeStr;
    std::cout << "\nTimestamp para consulta (formato HH:MM:SS, entre " 
              << timestampStrings.front() << " y " << timestampStrings.back() << "): ";
    std::cin >> queryTimeStr;

    double queryTimestamp;
    try {
        queryTimestamp = timeStringToHours(queryTimeStr);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    if (queryTimestamp < timestamps.front() || queryTimestamp > timestamps.back()) {
        std::cerr << "Error: El timestamp está fuera del rango de datos" << std::endl;
        return 1;
    }

    // Cifrar timestamp de consulta (cliente)
    start = std::chrono::high_resolution_clock::now();
    std::vector<double> timestampVec = {queryTimestamp};
    Plaintext ptTimestamp = cryptoContext->MakeCKKSPackedPlaintext(timestampVec);
    auto encryptedTimestamp = cryptoContext->Encrypt(keyPair.publicKey, ptTimestamp);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "Timestamp cifrado. Tiempo: " << elapsed.count() 
              << " segundos. Memoria: " << getMemoryUsage() << " KB" << std::endl;

    // Interpolación homomórfica (servidor)
    start = std::chrono::high_resolution_clock::now();
    auto encryptedResult = homomorphicLagrangeInterpolation(
        cryptoContext, temperatures, timestamps, encryptedTimestamp, keyPair.publicKey);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "Interpolación completada. Tiempo: " << elapsed.count() 
              << " segundos. Memoria: " << getMemoryUsage() << " KB" << std::endl;

    // Descifrar resultado (cliente)
    start = std::chrono::high_resolution_clock::now();
    Plaintext decryptedResult;
    cryptoContext->Decrypt(keyPair.secretKey, encryptedResult, &decryptedResult);
    decryptedResult->SetLength(1);
    double result = decryptedResult->GetRealPackedValue()[0];
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "Descifrado completado. Tiempo: " << elapsed.count() 
              << " segundos. Memoria: " << getMemoryUsage() << " KB" << std::endl;

    // Calcular valor esperado (interpolación no criptográfica para comparae)
    double expectedTemp = 0.0;
    for (size_t j = 0; j < temperatures.size(); j++) {
        double term = temperatures[j];
        for (size_t i = 0; i < timestamps.size(); i++) {
            if (i != j) {
                term *= (queryTimestamp - timestamps[i]) / (timestamps[j] - timestamps[i]);
            }
        }
        expectedTemp += term;
    }

    // Mostrar resultados
    std::cout << "\nResultados:" << std::endl;
    std::cout << "Timestamp consultado: " << queryTimeStr << " (" << queryTimestamp << " horas)" << std::endl;
    std::cout << "Temperatura estimada (HE): " << result << " °C" << std::endl;
    std::cout << "Temperatura esperada: " << expectedTemp << " °C" << std::endl;
    std::cout << "Diferencia: " << std::abs(result - expectedTemp) << " °C" << std::endl;
    std::cout << "Uso de memoria final: " << getMemoryUsage() << " KB" << std::endl;

    return 0;
}
