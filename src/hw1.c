#include "hw1.h"

void print_packet_sf(unsigned char packet[])
{
    unsigned int src_addr = 0;
    src_addr |= packet[0] << 20;
    src_addr |= packet[1] << 12;
    src_addr |= packet[2] << 4;
    src_addr |= packet[3] >> 4;
    printf("Source Address: %d\n", src_addr);
    
    unsigned int dest_addr = 0;
    dest_addr |= (packet[3] << 4) << 24;
    dest_addr |= packet[4] << 16;
    dest_addr |= packet[5] << 8;
    dest_addr |= packet[6];
    printf("Destination Address: %d\n", dest_addr);
    
    unsigned int src_port = 0;
    src_port |= packet[7] >> 4;
    printf("Source Port: %d\n", src_port);
    
    unsigned int dest_port = 0;
    dest_port |= (packet[7] & 0x0F);
    printf("Destination Port: %d\n", dest_port);
    
    unsigned int fragment_offset = 0;
    fragment_offset |= (packet[8] & 0xFF) << 6;
    fragment_offset |= (packet[9] & 0xFC) >> 2;
    printf("Fragment Offset: %d\n", fragment_offset);
    
    unsigned int packet_length = 0;
    packet_length |= (packet[9] & 0x03) << 12;
    packet_length |= packet[10] << 4;
    packet_length |= (packet[11] & 0xF0) >> 4;
    printf("Packet Length: %d\n", packet_length);
    
    unsigned int max_hop_count = 0;
    max_hop_count |= (packet[11] & 0x0F) << 1;
    max_hop_count |= (packet[12] & 0x80) >> 7;
    printf("Maximum Hop Count: %d\n", max_hop_count);
    
    unsigned int checksum = 0;
    checksum |= (packet[12] & 0x7F) << 16;
    checksum |= packet[13] << 8;
    checksum |= packet[14];
    printf("Checksum: %d\n", checksum);
    
    unsigned int compression_scheme = 0;
    compression_scheme |= (packet[15] & 0xC0) >> 6;
    printf("Compression Scheme: %d\n", compression_scheme);
    
    unsigned int traffic_class = 0;
    traffic_class = packet[15] & 0x3F;
    printf("Traffic Class: %d\n", traffic_class);
    
    printf("Payload: ");
    for(int i = 16; i < packet_length; i += 4) {
        int payload = (packet[i] << 24) | (packet[i + 1] << 16) | (packet[i + 2] << 8) | packet[i + 3];
        if(i > 16) {
            printf(" ");
        }
        printf("%d", payload);
    }
    printf("\n");
    //(void)packet;
}

unsigned int compute_checksum_sf(unsigned char packet[])
{
    unsigned long finalRes = 0;

    unsigned int src_addr = 0;
    src_addr |= packet[0] << 20;
    src_addr |= packet[1] << 12;
    src_addr |= packet[2] << 4;
    src_addr |= packet[3] >> 4;
    finalRes += src_addr;
    
    unsigned int dest_addr = 0;
    dest_addr |= (packet[3] << 4) << 24;
    dest_addr |= packet[4] << 16;
    dest_addr |= packet[5] << 8;
    dest_addr |= packet[6];
    finalRes += dest_addr;
    
    unsigned int src_port = 0;
    src_port |= packet[7] >> 4;
    finalRes += src_port;
    
    unsigned int dest_port = 0;
    dest_port |= (packet[7] & 0x0F);
    finalRes += dest_port;
    
    unsigned int fragment_offset = 0;
    fragment_offset |= (packet[8] & 0xFF) << 6;
    fragment_offset |= (packet[9] & 0xFC) >> 2;
    finalRes += fragment_offset;
    
    unsigned int packet_length = 0;
    packet_length |= (packet[9] & 0x03) << 12;
    packet_length |= packet[10] << 4;
    packet_length |= (packet[11] & 0xF0) >> 4;
    finalRes += packet_length;
    
    unsigned int max_hop_count = 0;
    max_hop_count |= (packet[11] & 0x0F) << 1;
    max_hop_count |= (packet[12] & 0x80) >> 7;
    finalRes += max_hop_count;
    
    unsigned int compression_scheme = 0;
    compression_scheme |= (packet[15] & 0xC0) >> 6;
    finalRes += compression_scheme;
    
    unsigned int traffic_class = 0;
    traffic_class = packet[15] & 0x3F;
    finalRes += traffic_class;
    
    for(int i = 16; i < packet_length; i += 4) {
        int payload = (packet[i] << 24) | (packet[i + 1] << 16) | (packet[i + 2] << 8) | packet[i + 3];
        finalRes += labs(payload);
    }
    
    unsigned int result = (unsigned int)(finalRes%8388607);
    return result;
}

unsigned int reconstruct_array_sf(unsigned char *packets[], unsigned int packets_len, int *array, unsigned int array_len) {
    unsigned int finalRes = 0;
    for(int i = 0; i < packets_len; i++)
    {
        unsigned char *currPacket = packets[i];
        unsigned int checksum1 = compute_checksum_sf(currPacket);
        unsigned int checksum2 = 0;
        checksum2 |= (currPacket[12] & 0x7F) << 16;
        checksum2 |= currPacket[13] << 8;
        checksum2 |= currPacket[14];
        if(checksum1 != checksum2) continue;
        unsigned int fragment_offset = 0;
        fragment_offset |= (currPacket[8] & 0xFF) << 6;
        fragment_offset |= (currPacket[9] & 0xFC) >> 2;
        unsigned int targetIndex = fragment_offset/4;
        if(targetIndex >= array_len) continue;
        unsigned int packet_length = 0;
        packet_length |= (currPacket[9] & 0x03) << 12;
        packet_length |= currPacket[10] << 4;
        packet_length |= (currPacket[11] & 0xF0) >> 4;
        unsigned int totalPayload = (packet_length-16)/4;
        for(int k = 0; (targetIndex + k) < array_len && k < totalPayload; k++)
        {
            int plIndex = (k*4) + 16;
            int actualPl = (currPacket[plIndex] << 24) | (currPacket[plIndex+1] << 16) | (currPacket[plIndex+2] << 8) | (currPacket[plIndex+3]);
            array[targetIndex + k] = actualPl;
            finalRes++;
        }
    }
    return finalRes;
    // (void)packets;
    // (void)packets_len;
    // (void)array;
    // (void)array_len;
    // return -1;
}

// Helper function to convert an integer to bytes in network byte order
void int_to_bytes(unsigned int value, unsigned char *bytes, int num_bytes) {
    for (int i = num_bytes - 1; i >= 0; --i) {
        bytes[i] = (value >> (8 * (num_bytes - 1 - i))) & 0xFF;
    }
}

unsigned int min(unsigned int a, unsigned int b) {
    return (a < b) ? a : b;
}

unsigned int packetize_array_sf(int *array, unsigned int array_len, 
                                unsigned char *packets[], unsigned int packets_len,
                                unsigned int max_payload, unsigned int src_addr, 
                                unsigned int dest_addr, unsigned int src_port, 
                                unsigned int dest_port, unsigned int maximum_hop_count,
                                unsigned int compression_scheme, unsigned int traffic_class) {
    const unsigned int HEADER_SIZE = 16;
    unsigned int num_packets_created = 0;
    unsigned int fragment_offset = 0;

    for (unsigned int i = 0; i < array_len; i += max_payload / sizeof(int)) {
        unsigned int num_ints_in_this_packet = min((array_len - i), max_payload / sizeof(int));
        unsigned int payload_size = num_ints_in_this_packet * sizeof(int);
        unsigned int packet_size = HEADER_SIZE + payload_size;

        if (num_packets_created >= packets_len) {
            break;
        }

        packets[num_packets_created] = (unsigned char *)malloc(packet_size);
        if (!packets[num_packets_created]) {
            break;
        }

        // Clear the packet memory
        memset(packets[num_packets_created], 0, packet_size);

        // Source and destination address
        int_to_bytes(src_addr, &packets[num_packets_created][0], 4);
        int_to_bytes(dest_addr, &packets[num_packets_created][4], 4);

        // Source and destination ports
        packets[num_packets_created][7] = (src_port << 4) | dest_port;

        // Fragment offset
        int_to_bytes(fragment_offset, &packets[num_packets_created][8], 2);

        // Packet length
        int_to_bytes(packet_size, &packets[num_packets_created][10], 2);

        // Maximum Hop Count, Compression Scheme and Traffic Class
        packets[num_packets_created][11] = maximum_hop_count;
        packets[num_packets_created][12] = (compression_scheme << 6) | (traffic_class & 0x3F);

        // Payload
        for (unsigned int j = 0; j < num_ints_in_this_packet; ++j) {
            int_to_bytes(array[i + j], &packets[num_packets_created][HEADER_SIZE + j * 4], 4);
        }

        // Checksum (needs to be calculated after the rest of the packet is filled)
        unsigned int checksum = compute_checksum_sf(packets[num_packets_created]);
        int_to_bytes(checksum, &packets[num_packets_created][13], 2);

        // Update fragment_offset and num_packets_created for the next packet
        fragment_offset += num_ints_in_this_packet * sizeof(int);
        ++num_packets_created;
    }

    return num_packets_created;
}

// Helper function to find the minimum of two values






