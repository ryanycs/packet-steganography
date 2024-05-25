#include <pcap.h>

enum Protocal {
    IP,
    TCP,
    UDP,
    RTP,
};

/// @brief
/// @param filename pcap file name
/// @param protocal protocol type
/// @param start start index
/// @param size  read size
/// @param data return data
/// @param data_size return data size
/// @return 0 if success, 1 if failed
int read_pcap(const char *filename, int protocal, int start, int size, char **data, int *data_size);