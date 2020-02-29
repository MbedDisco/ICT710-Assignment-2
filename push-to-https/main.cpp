#include <mbed.h>
#include "https_request.h"

// pass in the root certificates that you trust, there is no central CA registry in Mbed OS
const char SSL_CA_PEM[] = "-----BEGIN CERTIFICATE-----\n"
"MIIEGTCCAwGgAwIBAgIJQgAABMReWJq6MA0GCSqGSIb3DQEBCwUAMFQxGTAXBgNV\n"
"BAoMEEFPIEthc3BlcnNreSBMYWIxNzA1BgNVBAMMLkthc3BlcnNreSBBbnRpLVZp\n"
"cnVzIFBlcnNvbmFsIFJvb3QgQ2VydGlmaWNhdGUwHhcNMTgxMTI4MDAwMDAwWhcN\n"
"MjEwMjI3MDQ0NDQyWjCBpTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3Ju\n"
"aWExFDASBgNVBAcTC0xvcyBBbmdlbGVzMTwwOgYDVQQKEzNJbnRlcm5ldCBDb3Jw\n"
"b3JhdGlvbiBmb3IgQXNzaWduZWQgTmFtZXMgYW5kIE51bWJlcnMxEzARBgNVBAsT\n"
"ClRlY2hub2xvZ3kxGDAWBgNVBAMTD3d3dy5leGFtcGxlLm9yZzCCASIwDQYJKoZI\n"
"hvcNAQEBBQADggEPADCCAQoCggEBALiw7yxkXdqQoN1WRITvMIeAtMPKVTwXswZL\n"
"RL15KeRLRCTAZasTvx005wc7nE6BuQmEnXhYjqh6S7lanpvdxalYyghHKzl3yhz5\n"
"2r9hYkuAr7bUJLCZ+5UXC7mW1B4CF519HJQNScaMPI3iHEAFOc4wHDV+67sP/UMw\n"
"P2Chvm531mBmPxRSCpdcKBa2b+jDPaolQKYGwkyt749WtjGvtCgUCAesEuaVn8du\n"
"irRjfCBq9UaXFh8RbIB99aKVN3bC6mz/y5nfWvx8nx7ZqTDL37WmXseeODnB6SVC\n"
"l5QVMeANEfKwKKw6apTChwBVSkz+OCswmrWJSwsSZHdU0tgNnPECAwEAAaOBmzCB\n"
"mDALBgNVHQ8EBAMCBaAwgYgGA1UdEQSBgDB+hwRduNgigg93d3cuZXhhbXBsZS5j\n"
"b22CD3d3dy5leGFtcGxlLm9yZ4ILZXhhbXBsZS5jb22CC2V4YW1wbGUuZWR1ggtl\n"
"eGFtcGxlLm5ldIILZXhhbXBsZS5vcmeCD3d3dy5leGFtcGxlLmVkdYIPd3d3LmV4\n"
"YW1wbGUubmV0MA0GCSqGSIb3DQEBCwUAA4IBAQCItPJbMKyg1SszV0JAPdGLCkDh\n"
"uaaJ6QBAE/0EtTWcDSRcaQNI/PdEOlsVyV/Lb4gxLy2wffl5LBted8NH+vFetmFL\n"
"dT7bii0RcUPGr+zxyFTj1ZinFt2niKj2mDh42q1xfvbmXMxr4/haLU4q7Hy/G78M\n"
"YQDRB8E20UVPrGzNevhkLtM9sAcPpmXTCG0NbIGNw1tZOFxxULmo04GqIfOasHfM\n"
"AZTTTPCU6nfDqNFEGydYi6KHDMHaWk6Z5J6GqTTy+li+hmzdH712MM7vZyEKHMCL\n"
"lfPuW16Gq/r5Hx+o+XbFjCXnlT5ZAyFyVOGZrLKx4Ueog3QjNIgFwxwU7lYg\n"
"-----END CERTIFICATE-----\n";
    
DigitalOut led(LED1);
InterruptIn button(USER_BUTTON);
Thread t;
EventQueue queue(32 * EVENTS_EVENT_SIZE);
Serial pc(USBTX, USBRX);
WiFiInterface *wifi;

const char *sec2str(nsapi_security_t sec)
{
    switch (sec) {
        case NSAPI_SECURITY_NONE:
            return "None";
        case NSAPI_SECURITY_WEP:
            return "WEP";
        case NSAPI_SECURITY_WPA:
            return "WPA";
        case NSAPI_SECURITY_WPA2:
            return "WPA2";
        case NSAPI_SECURITY_WPA_WPA2:
            return "WPA/WPA2";
        case NSAPI_SECURITY_UNKNOWN:
        default:
            return "Unknown";
    }
}

int scan_wifi() {
    WiFiAccessPoint *ap;

    printf("Scan:\n");
    int count = wifi->scan(NULL,0);
    if (count <= 0) {
        printf("scan() failed with return value: %d\n", count);
        return 0;
    }

    /* Limit number of network arbitrary to 15 */
    count = count < 15 ? count : 15;
    ap = new WiFiAccessPoint[count];
    count = wifi->scan(ap, count);
    if (count <= 0) {
        printf("scan() failed with return value: %d\n", count);
        return 0;
    }

    for (int i = 0; i < count; i++) {
        printf("Network: %s secured: %s BSSID: %hhX:%hhX:%hhX:%hhx:%hhx:%hhx RSSI: %hhd Ch: %hhd\n", ap[i].get_ssid(),
               sec2str(ap[i].get_security()), ap[i].get_bssid()[0], ap[i].get_bssid()[1], ap[i].get_bssid()[2],
               ap[i].get_bssid()[3], ap[i].get_bssid()[4], ap[i].get_bssid()[5], ap[i].get_rssi(), ap[i].get_channel());
    }
    printf("%d networks available.\n", count);

    delete[] ap;   

    return count; 
}


void pressed_handler() {
    int count;

    count = scan_wifi();
    if (count == 0) {
        pc.printf("No WIFI APs found - can't continue further.\n");
        return;
    }

    pc.printf("\nConnecting to %s...\n", MBED_CONF_APP_WIFI_SSID);
    int ret = wifi->connect(MBED_CONF_APP_WIFI_SSID, MBED_CONF_APP_WIFI_PASSWORD, NSAPI_SECURITY_WPA_WPA2);
    if (ret != 0) {
        pc.printf("\nConnection error: %d\n", ret);
        return;
    }

    pc.printf("Success\n\n");
    printf("MAC: %s\n", wifi->get_mac_address());
    printf("IP: %s\n", wifi->get_ip_address());
    printf("Netmask: %s\n", wifi->get_netmask());
    printf("Gateway: %s\n", wifi->get_gateway());
    printf("RSSI: %d\n\n", wifi->get_rssi());   

    HttpsRequest* request = new HttpsRequest(wifi, SSL_CA_PEM, HTTP_GET, "https://example.com");
    HttpResponse* response = request->send();

    // if response is NULL, check response->get_error()
    
    printf("status is %d - %s\n", response->get_status_code(), response->get_status_message());
    printf("body is:\n%s\n", response->get_body());
    
    delete request;// also clears out the response


    wifi->disconnect();
    pc.printf("\nDone\n");    
}

int main() {
    wifi = WiFiInterface::get_default_instance();
    if (!wifi) {
        printf("ERROR: No WiFiInterface found.\n");
        return -1;
    }

    t.start(callback(&queue, &EventQueue::dispatch_forever));
    button.fall(queue.event(pressed_handler));
    pc.printf("Starting\n");
    while(1) {
        led = !led;
        ThisThread::sleep_for(500);
    }
}
