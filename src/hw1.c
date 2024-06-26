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

unsigned int reconstruct_array_sf(unsigned char *packets[], 
    unsigned int packets_len, int *array, unsigned int array_len) {
    
    unsigned int finalRes = 0;
    for(unsigned int i = 0; i < packets_len; i++) {
        unsigned char *currPacket = packets[i];
        unsigned int checksum1 = compute_checksum_sf(currPacket); 
        unsigned int checksum2 = ((currPacket[12] & 0x7F) << 16) | (currPacket[13] << 8) | currPacket[14];
        
        if(checksum1 != checksum2) continue; 
        
        unsigned int fragment_offset = ((currPacket[8] & 0xFF) << 6) | ((currPacket[9] & 0xFC) >> 2);
        unsigned int targetIndex = fragment_offset / 4; 
        
        if(targetIndex >= array_len) continue; 
        
        unsigned int packet_length = ((currPacket[9] & 0x03) << 12) | (currPacket[10] << 4) | ((currPacket[11] & 0xF0) >> 4);
        unsigned int payloadLength = (packet_length - 16) / 4; 
        
        for(unsigned int k = 0; (k < payloadLength) && ((targetIndex + k) < array_len); k++) {
            unsigned int plIndex = 16 + (k * 4); 
            int actualPl = (currPacket[plIndex] << 24) | (currPacket[plIndex + 1] << 16) | (currPacket[plIndex + 2] << 8) | (currPacket[plIndex + 3]);
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
                        unsigned int compression_scheme, unsigned int traffic_class) 
{
    unsigned int finalRes = 0, fragment_offset = 0, totalPayload;
    for(int i = 0; i < array_len; i += (max_payload / 4)) 
    {
        if(((max_payload / 4) + i) > array_len) 
            totalPayload = array_len - i;
        else 
            totalPayload = max_payload / 4;

        
        unsigned int totalPacketSize = 16 + (totalPayload * 4);
        
        
        if(finalRes >= packets_len) 
            break;

        
        packets[finalRes] = malloc(totalPacketSize);
        if(packets[finalRes] == NULL) 
            break;

        for(unsigned int j = 0; j < totalPacketSize; j++) packets[finalRes][j] = 0;

        packets[finalRes][0] = (src_addr >> 20) & 0xFF;
        packets[finalRes][1] = (src_addr >> 12) & 0xFF;
        packets[finalRes][2] = (src_addr >> 4) & 0xFF;
        packets[finalRes][3] = ((src_addr & 0xF) << 4) | ((dest_addr >> 24) & 0xF);

        
        packets[finalRes][4] = (dest_addr >> 16) & 0xFF;
        packets[finalRes][5] = (dest_addr >> 8) & 0xFF;
        packets[finalRes][6] = dest_addr & 0xFF;

        
        packets[finalRes][7] = ((src_port & 0xF) << 4) | (dest_port & 0xF);

        
        packets[finalRes][8] = (fragment_offset >> 6) & 0xFF; 
        packets[finalRes][9] = (fragment_offset & 0x3F) << 2; 

        
        packets[finalRes][9] |= (totalPacketSize >> 12) & 0x3; 
        packets[finalRes][10] = (totalPacketSize >> 4) & 0xFF; 
        packets[finalRes][11] = (totalPacketSize & 0xF) << 4; 

        
        packets[finalRes][11] |= (maximum_hop_count >> 1) & 0xF;
        packets[finalRes][12] = (maximum_hop_count & 0x1) << 7;

        
        packets[finalRes][15] = (compression_scheme & 0x3) << 6;
        packets[finalRes][15] |= (traffic_class & 0x3F);

        
        int payloadIndex = 16;
        for(int k = 0; k < totalPayload; ++k)
        {
            int currPayload = array[k + i];
            packets[finalRes][payloadIndex++] = (currPayload >> 24) & 0xFF;
            packets[finalRes][payloadIndex++] = (currPayload >> 16) & 0xFF;
            packets[finalRes][payloadIndex++] = (currPayload >> 8) & 0xFF;
            packets[finalRes][payloadIndex++] = currPayload & 0xFF;
        }
        
        unsigned int checksum = compute_checksum_sf(packets[finalRes]);
        packets[finalRes][12] |= (checksum >> 16) & 0x7F; 
        packets[finalRes][13] = (checksum >> 8) & 0xFF;  
        packets[finalRes][14] = checksum & 0xFF;         

        fragment_offset += totalPayload * sizeof(int);

        finalRes++;
    }
    return finalRes;
}


