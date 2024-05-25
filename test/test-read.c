#include <utils.h>

int main() {
    char *data;
    int data_size;

    read_pcap("test.pcap", IP, 0, 5, &data, &data_size);

    for (int i = 0; i < data_size / 5; i++) {
        for (int j = 0; j < 5; j++) {
            printf("%02x ", data[i * 5 + j]);
        }
        printf("\n");
    }
    return 0;
}