#include <utils.h>

int main() {
    char *data;
    int data_size;

    read_pcap("test.pcap", IP, 5, 5, &data, &data_size);

    for (int i = 0; i < data_size / 5; i++) {
        for (int j = 0; j < 5; j++) {
            printf("%02x ", (unsigned char)data[i * 5 + j]);
        }
        printf("\n");
    }

    read_pcap("test.pcap", UDP, 3, 5, &data, &data_size);

    for (int i = 0; i < data_size / 5; i++) {
        for (int j = 0; j < 5; j++) {
            printf("%02x ", (unsigned char)data[i * 5 + j]);
        }
        printf("\n");
    }
    return 0;
}
