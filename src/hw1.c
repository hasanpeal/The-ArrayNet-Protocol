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

unsigned int packetize_array_sf(int *array, unsigned int array_len, 
                                unsigned char *packets[], unsigned int packets_len,
                                unsigned int max_payload, unsigned int src_addr, 
                                unsigned int dest_addr, unsigned int src_port, 
                                unsigned int dest_port, unsigned int maximum_hop_count,
                                unsigned int compression_scheme, unsigned int traffic_class) {
    // Define the header size based on the provided structure
    const unsigned int HEADER_SIZE = 16;
    unsigned int num_packets_created = 0;
    unsigned int fragment_offset = 0;
    unsigned int array_index = 0;

    // Calculate the number of packets needed
    unsigned int total_packets_needed = (array_len * sizeof(int) + max_payload - 1) / max_payload;
    if (packets_len < total_packets_needed) {
        total_packets_needed = packets_len;
    }

    // Packetize the array
    for (unsigned int i = 0; i < total_packets_needed; i++) {
        // Calculate the payload length for the current packet
        unsigned int payload_length = (array_index + max_payload/sizeof(int) <= array_len) ? 
                                      max_payload : (array_len - array_index) * sizeof(int);

        // Calculate the total packet length
        unsigned int packet_length = HEADER_SIZE + payload_length;

        // Allocate memory for the new packet
        packets[i] = (unsigned char *)malloc(packet_length);
        if (packets[i] == NULL) {
            // Memory allocation failed, break out of the loop
            break;
        }

        // Clear the memory
        memset(packets[i], 0, packet_length);

        // Fill in the header fields
        packets[i][0] = (src_addr >> 20) & 0xFF;
        packets[i][1] = (src_addr >> 12) & 0xFF;
        packets[i][2] = (src_addr >> 4) & 0xFF;
        packets[i][3] = ((src_addr & 0xF) << 4) | ((dest_addr >> 28) & 0xF);
        packets[i][4] = (dest_addr >> 20) & 0xFF;
        packets[i][5] = (dest_addr >> 12) & 0xFF;
        packets[i][6] = (dest_addr >> 4) & 0xFF;
        packets[i][7] = ((dest_addr & 0xF) << 4) | (src_port << 2) | (dest_port >> 2);
        packets[i][8] = (fragment_offset >> 8) & 0xFF;
        packets[i][9] = ((fragment_offset & 0xFC) << 2) | ((packet_length >> 12) & 0x3);
        packets[i][10] = (packet_length >> 4) & 0xFF;
        packets[i][11] = ((packet_length & 0xF) << 4) | (maximum_hop_count >> 1);
        packets[i][12] = ((maximum_hop_count & 0x1) << 7); // Checksum will be filled later
        // bytes 13, 14 will be for checksum
        packets[i][15] = (compression_scheme << 6) | traffic_class;

        // Fill in the payload
        for (unsigned int j = 0; j < payload_length; j += 4) {
            packets[i][HEADER_SIZE + j] = (array[array_index] >> 24) & 0xFF;
            packets[i][HEADER_SIZE + j + 1] = (array[array_index] >> 16) & 0xFF;
            packets[i][HEADER_SIZE + j + 2] = (array[array_index] >> 8) & 0xFF;
            packets[i][HEADER_SIZE + j + 3] = array[array_index] & 0xFF;
            array_index++;
        }

        // Compute and fill in the checksum
        unsigned int checksum = compute_checksum_sf(packets[i]);
        packets[i][12] |= (checksum >> 16) & 0x7F;
        packets[i][13] = (checksum >> 8) & 0xFF;
        packets[i][14] = checksum & 0xFF;

        // Increment the fragment offset
        fragment_offset += payload_length;

        // Increment the number of packets created
        num_packets_created++;
    }

    return num_packets_created;
}


