#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define SIZE 4               // 4x4 sous-matrice
#define BLOCK_SIZE (SIZE*SIZE*4) // 64 octets par bloc

// inversion centrale d'une sous-matrice
void reverse_symmetry(uint8_t input[SIZE][SIZE], uint8_t output[SIZE][SIZE])
{
    for (int i = 0; i < SIZE; i++)
        for (int j = 0; j < SIZE; j++)
            output[i][j] = input[SIZE - 1 - i][SIZE - 1 - j];
}

// soustraction de trace/2
void subtract_trace(uint8_t matrix[SIZE][SIZE], uint8_t trace_half)
{
    for (int i = 0; i < SIZE; i++)
        for (int j = 0; j < SIZE; j++)
            matrix[i][j] = (uint8_t)(matrix[i][j] - trace_half);
}

// XOR avec la clé
void xor_with_key(uint8_t matrix[SIZE][SIZE], uint8_t key[SIZE][SIZE])
{
    for (int i = 0; i < SIZE; i++)
        for (int j = 0; j < SIZE; j++)
            matrix[i][j] ^= key[i][j];
}

// rotation 90° à droite
void rotate_right(uint8_t input[SIZE][SIZE], uint8_t output[SIZE][SIZE])
{
    for (int i = 0; i < SIZE; i++)
        for (int j = 0; j < SIZE; j++)
            output[i][j] = input[SIZE - 1 - j][i];
}

// calcul de trace(K)/2
uint8_t compute_trace_half(uint8_t key[SIZE][SIZE])
{
    uint16_t trace = 0;
    for (int i = 0; i < SIZE; i++)
        trace += key[i][i];
    return (uint8_t)(trace / 2);
}

// déchiffrement d'une sous-matrice 4x4
void decrypt_block(uint8_t cipher[SIZE][SIZE],
                   uint8_t key[SIZE][SIZE],
                   uint8_t output[SIZE][SIZE])
{
    uint8_t tmp1[SIZE][SIZE];
    uint8_t tmp2[SIZE][SIZE];
    uint8_t trace_half = compute_trace_half(key);

    reverse_symmetry(cipher, tmp1);
    subtract_trace(tmp1, trace_half);
    xor_with_key(tmp1, key);
    rotate_right(tmp1, tmp2);

    for (int i = 0; i < SIZE; i++)
        for (int j = 0; j < SIZE; j++)
            output[i][j] = tmp2[i][j];
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s input.bin output.bin\n", argv[0]);
        return 1;
    }

    FILE *fin = fopen(argv[1], "rb");
    FILE *fout = fopen(argv[2], "wb");
    if (!fin || !fout)
    {
        perror("File error");
        return 1;
    }

    uint8_t buffer[BLOCK_SIZE];
    uint8_t M1[SIZE][SIZE], M2[SIZE][SIZE], M3[SIZE][SIZE], M4[SIZE][SIZE];
    uint8_t key[SIZE][SIZE] = {
        {36, 33, 36, 35},
        {40, 60, 62, 41},
        {38, 35, 43, 42},
        {45, 47, 40, 41}
    };

    while (fread(buffer, 1, BLOCK_SIZE, fin) == BLOCK_SIZE)
    {
        // remplir les 4 sous-matrices
        for (int i = 0; i < SIZE; i++)
            for (int j = 0; j < SIZE; j++)
            {
                M1[i][j] = buffer[i*SIZE + j];
                M2[i][j] = buffer[SIZE*SIZE + i*SIZE + j];
                M3[i][j] = buffer[2*SIZE*SIZE + i*SIZE + j];
                M4[i][j] = buffer[3*SIZE*SIZE + i*SIZE + j];
            }

        // déchiffrer chaque sous-matrice
        decrypt_block(M1, key, M1);
        decrypt_block(M2, key, M2);
        decrypt_block(M3, key, M3);
        decrypt_block(M4, key, M4);

        // réassembler correctement ligne par ligne
        int index = 0;
        for (int i = 0; i < SIZE; i++)
        {
            for (int j = 0; j < SIZE; j++) buffer[index++] = M1[i][j];
            for (int j = 0; j < SIZE; j++) buffer[index++] = M2[i][j];
        }
        for (int i = 0; i < SIZE; i++)
        {
            for (int j = 0; j < SIZE; j++) buffer[index++] = M3[i][j];
            for (int j = 0; j < SIZE; j++) buffer[index++] = M4[i][j];
        }

        fwrite(buffer, 1, BLOCK_SIZE, fout);
    }

    fclose(fin);
    fclose(fout);

    printf("[+] Déchiffrement terminé, résultat dans %s\n", argv[2]);
    return 0;
}
