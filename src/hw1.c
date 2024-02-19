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
}

unsigned int packetize_array_sf(int *array, unsigned int array_len,
                                unsigned char *packets[], unsigned int packets_len,
                                unsigned int max_payload, unsigned int src_addr,
                                unsigned int dest_addr, unsigned int src_port,
                                unsigned int dest_port, unsigned int maximum_hop_count,
                                unsigned int compression_scheme, unsigned int traffic_class) {
    unsigned int packets_created = 0;
    const unsigned int header_size = 16; // The fixed header size
    const unsigned int max_integers_per_packet = (max_payload - header_size) / sizeof(int); // Max integers per payload

    for (unsigned int i = 0, fragment_offset = 0; i < array_len; i += max_integers_per_packet, fragment_offset += max_integers_per_packet * sizeof(int)) {
        unsigned int end_index = i + max_integers_per_packet > array_len ? array_len : i + max_integers_per_packet;
        unsigned int current_payload_size = (end_index - i) * sizeof(int);
        unsigned int packet_size = header_size + current_payload_size;

        if (packets_created >= packets_len) break;

        packets[packets_created] = (unsigned char *)malloc(packet_size);
        if (!packets[packets_created]) break; // Allocation check

        // Construct packet header
        packets[packets_created][0] = src_addr >> 24;
        packets[packets_created][1] = (src_addr >> 16) & 0xFF;
        packets[packets_created][2] = (src_addr >> 8) & 0xFF;
        packets[packets_created][3] = src_addr & 0xFF;

        packets[packets_created][4] = dest_addr >> 24;
        packets[packets_created][5] = (dest_addr >> 16) & 0xFF;
        packets[packets_created][6] = (dest_addr >> 8) & 0xFF;
        packets[packets_created][7] = dest_addr & 0xFF;

        // Corrected port and fragment offset handling
        packets[packets_created][8] = (src_port & 0xF) << 4 | (dest_port & 0xF);
        packets[packets_created][9] = (fragment_offset >> 8) & 0xFF;
        packets[packets_created][10] = fragment_offset & 0xFF;

        packets[packets_created][11] = (packet_size >> 8) & 0xFF;
        packets[packets_created][12] = packet_size & 0xFF;

        // Maximum Hop Count, Compression Scheme, and Traffic Class
        packets[packets_created][13] = (maximum_hop_count & 0x1F) << 3 | (compression_scheme & 0x03) << 1 | (traffic_class >> 5);
        packets[packets_created][14] = (traffic_class & 0x1F) << 3;

        // Zero out checksum for calculation
        packets[packets_created][15] = 0;
        packets[packets_created][16] = 0;
        packets[packets_created][17] = 0;

        // Payload construction
        memcpy(&packets[packets_created][18], &array[i], current_payload_size);

        // Calculate and insert checksum
        unsigned int checksum = compute_checksum_sf(packets[packets_created]);
        packets[packets_created][15] = (checksum >> 16) & 0x7F; // High part of checksum
        packets[packets_created][16] = (checksum >> 8) & 0xFF;  // Middle part of checksum
        packets[packets_created][17] = checksum & 0xFF;         // Low part of checksum

        packets_created++;
    }
 return packets_created;
}

            

