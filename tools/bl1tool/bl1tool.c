#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
//#include <unistd.h>
#include <getopt.h>

#include <time.h>

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/pem.h>

typedef int (*cmd_func_t)(int argc, char **argv, char* cmd);

struct command {
    const char *name;
    cmd_func_t func;
};

typedef struct bl1_head {
    uint32_t size_in_blocks;
    uint32_t chksum;
    uint32_t unk1;
    uint32_t unk2;
} bl1_head;

typedef struct samsung_pubkey {
    uint32_t pubkey_n_len;
    uint8_t pubkey_n[0x100];
    uint32_t pubkey_e_len;
    uint8_t pubkey_e[0x4];
} samsung_pubkey;

typedef struct bl1_footer {
    uint32_t signer_version;
    char ap_info[4]; //SLSI
    uint64_t date; //unix date
    uint32_t rp_count; //rollback protection'nt
    uint32_t sign_type; //we support 0 right now
    uint8_t unk1[0x20];
    uint8_t pubkey_bl31[0x10c];
    uint8_t brom_funcs[0x80]; //bootrom fills this with function ptrs in case of secure boot, we keep it empty
    uint16_t id1; //Two IDs, if set up this needs to be set properly, otherwise bootrom might refuse our image. Maybe ID of the device an image is made for?
    uint16_t id2; //It seems like either id1, id2, or none are checked, they are never checked together, at least on 7870
    uint8_t unk4[0x8]; //signature is up to this point?
    samsung_pubkey pubkey_bl1;
    uint8_t hmac_bl1[0x20];
    uint32_t sigsize;
    uint8_t signature_bl1[0x100];
} bl1_footer;

void xor_buffers(uint8_t *out, uint8_t *a, uint8_t *b, uint32_t len) {
    for (uint32_t i = 0; i < len; i++) {
        out[i] = a[i] ^ b[i];
    }
}

void reverse_bytes(uint32_t* out, const uint32_t* in, size_t len) {
//void reverse_bytes(uint8_t* out, const uint8_t* in, size_t len) {
    for (size_t i = 0; i < len; i++) {
        //out[i] = in[len - 1 - i];
        out[len - 1 - i] = ((in[i] & 0xff) << 24) | ((in[i] & 0xff00) << 8) | ((in[i] & 0xff0000) >> 8) | ((in[i] & 0xff000000) >> 24);
        //out[i] = ((in[i] & 0xff) << 24) | ((in[i] & 0xff00) << 8) | ((in[i] & 0xff0000) >> 8) | ((in[i] & 0xff000000) >> 24);
    }
}

void fill_random_array(uint8_t* out, uint32_t len) {
    for (int i = 0; i < len; i++) {
        out[i] = rand();
    }
}

void dump_hex(uint8_t* in, uint32_t len, char* text) {
    printf("%s", text);
    for (int i = 0; i < len; i++) {
        printf(" %02x", in[i]);
    }
    printf("\n");
}

int open_bl1_noheader(char* filename, uint8_t** buffer_out, uint32_t* bl1_size_out, uint8_t force_open, uint8_t expand_with_footer, uint32_t force_size) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Failed to open input file");
        return 1;
    }

    fseek(file, 0L, SEEK_END);
    long sz = ftell(file);
    fseek(file, 0L, SEEK_SET);
    if (sz < 0) {
        fprintf(stderr, "Unable to read file size!\n");
        fclose(file);
        return 1;
    }

    if (sz == 0) {
        fprintf(stderr, "Empty input file!\n");
        fclose(file);
        return 1;
    }

    if (!expand_with_footer)
        if (sz & 0x1ff != 0) {
            fprintf(stderr, "File size not a multiple of block size (512)!\n");
            fclose(file);
            return 1;
        }

    uint32_t bl1_size = (uint32_t)sz;

    if (expand_with_footer) {
        bl1_size += sizeof(bl1_footer);
        //round up
        bl1_size = ((bl1_size + 0x1ff) & ~0x1ff);
        if (force_size) {
            if (force_size < bl1_size) {
                fprintf(stderr, "Forced size too small!\n");
                fclose(file);
                return 1;
            }
            if (force_size & 0x1ff != 0) {
                fprintf(stderr, "Forced size not a multiple of block size (512)!\n");
                fclose(file);
                return 1;
            }
            bl1_size = force_size;
        }
    }

    uint8_t* buffer = malloc(bl1_size);
    if (!buffer) {
        fprintf(stderr, "Memory allocation failed!\n");
        fclose(file);
        return 1;
    }

    size_t read_len = fread(buffer, 1, sz, file);
    fclose(file);

    if (read_len != sz) {
        fprintf(stderr, "Failed to read full BL1!\n");
        free(buffer);
        return 1;
    }

    if (!force_open)
        for (uint32_t i = 0; i < sizeof(bl1_head); i++) {
            if (buffer[i] != 0) {
                fprintf(stderr, "BL1 head not empty!\n");
                free(buffer);
                return 1;
            }
        }

    printf("Read full BL1 binary!\n");

    if (expand_with_footer) {
        bl1_head* header = (bl1_head *)buffer;
        header->size_in_blocks = bl1_size >> 9;
        printf("Set header size in blocks!\n");
    }

    *buffer_out = buffer;
    *bl1_size_out = bl1_size;
    return 0;
}

int open_bl1(char* filename, uint8_t** buffer_out, uint32_t* bl1_size_out) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Failed to open input file");
        return 1;
    }

    uint32_t header_size;
    size_t read_len = fread(&header_size, 1, 4, file);
    if (read_len != 4) {
        fprintf(stderr, "Unable to read file size in header!\n", filename);
        return 1;
    }

    uint32_t bl1_size = header_size << 9;
    uint8_t* buffer = malloc(bl1_size);
    if (!buffer) {
        fprintf(stderr, "Memory allocation failed!\n");
        fclose(file);
        return 1;
    }

    printf("Read BL1 size from header: 0x%02x blocks (0x%04x bytes)\n", header_size, bl1_size);

    ((uint32_t*)buffer)[0] = header_size;
    read_len = fread(&buffer[4], 1, bl1_size - 4, file);
    fclose(file);

    if (read_len != bl1_size - 4) {
        fprintf(stderr, "Failed to read rest of BL1!\n");
        free(buffer);
        return 1;
    }

    printf("Read full BL1 binary!\n");
    *buffer_out = buffer;
    *bl1_size_out = bl1_size;
    return 0;
}

int save_fixlen(char* filename, uint32_t len, char* name, uint8_t* buf) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        fprintf(stderr, "Failed to open output file for %s: %s", name, strerror(errno));
        return 1;
    }

    if (fwrite(buf, len, 1, file) != 1) {
        fprintf(stderr, "Writing output %s failed!\n", name);
        fclose(file);
        return 1;
    }
    fclose(file);
    return 0;
}

int open_fixlen(char* filename, uint32_t len, char* name, uint8_t* buf) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Failed to open input file for %s: %s", name, strerror(errno));
        return 1;
    }

    size_t read_len = fread(buf, 1, len, file);
    if (read_len != len) {
        fprintf(stderr, "Unable to read %s!\n", name);
        fclose(file);
        return 1;
    }
    fclose(file);
    return 0;
}

int open_efuse(char* filename, uint8_t* buf) {
    return open_fixlen(filename, 0x20, "efuse", buf);
}

int verify_checksum(uint8_t* buffer, uint32_t bl1_size, bl1_head* header) {
    printf("Checking checksum in header...");
    uint32_t header_hash[SHA256_DIGEST_LENGTH / 4];
    SHA256(&buffer[0x10], bl1_size - 0x10, (char*)header_hash);
    if (header_hash[0] == header->chksum) {
        printf("OK! (%08x)\n", header->chksum);
        return 0;
    } else {
        printf("FAIL! (%08x, should be %08x)\n", header_hash[0], header->chksum);
        return 1;
    }
}

int verify_checksum_main(int argc, char *argv[], char* cmd) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <bl1>\n", cmd);
        return 1;
    }

    uint32_t bl1_size;
    uint8_t* buffer;
    if (open_bl1(argv[1], &buffer, &bl1_size))
        return 1;

    bl1_head* header = (bl1_head *)buffer;
//    bl1_footer* footer = (bl1_footer *)&buffer[bl1_size - 0x400];

    int ret = verify_checksum(buffer, bl1_size, header);
    free(buffer);
    return ret;
}

int verify_pubkey(bl1_footer* footer, uint8_t* efuse_buf) {
    uint8_t hmac_key[0x20];
    uint8_t hmac_result[0x20];
    printf("Checking BL1 pubkey using efuse...");

    xor_buffers(hmac_key, efuse_buf, footer->hmac_bl1, 0x20);
    HMAC(EVP_sha256(), hmac_key, sizeof(hmac_key), (char*)&footer->pubkey_bl1, sizeof(footer->pubkey_bl1), hmac_result, NULL);

    int ret;
    if (memcmp(hmac_result, footer->hmac_bl1, 0x20) == 0) {
        printf("OK!\n");
        ret = 0;
    } else {
        printf("FAIL!\n");
        ret = 1;
    }
}

int verify_pubkey_main(int argc, char *argv[], char* cmd) {
    if (argc < 2) {
        fprintf(stderr, "Usage: TODO!\n", cmd);
        return 1;
    }

    static struct option long_options[] = {
        {"input", required_argument, 0, 'i'},
        {"efuse", required_argument, 0, 'e'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    char* input = NULL;
    char* efuse = NULL;
    optind = 1;

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "i:e:h",
                                  long_options, &option_index)) != -1) {
        switch (opt) {
        case 'i':
            input = optarg;
            break;
        case 'e':
            efuse = optarg;
            break;
        case 'h':
            fprintf(stderr, "Usage: TODO!\n", cmd);
            return 1;
            break;
        case '?':
            return 1;
            break;
        default:
            fprintf(stderr, "Unknown option\n");
            return 1;
        }
    }

    if (optind < argc) {
        if (input) {
            fprintf(stderr, "Options parse error!\n");
            return 1;
        }

        input = argv[optind++];
    }

    if (optind < argc) {
        fprintf(stderr, "Options parse error!\n");
        return 1;
    }

    if (!input) {
        fprintf(stderr, "No input file!\n");
        return 1;
    }
        
    if (!efuse) {
        fprintf(stderr, "No efuse file!\n");
        return 1;
    }

    uint32_t bl1_size;
    uint8_t* buffer;
    if (open_bl1(input, &buffer, &bl1_size))
        return 1;

    uint8_t efuse_buf[0x20];
    if (open_efuse(efuse, efuse_buf))
        return 1;

    bl1_footer* footer = (bl1_footer *)&buffer[bl1_size - sizeof(bl1_footer)];

    int ret = verify_pubkey(footer, efuse_buf);

    free(buffer);
    return ret;
}

int verify_signature(uint8_t* buffer, uint32_t bl1_size) {
    bl1_head* header = (bl1_head *)buffer;
    bl1_footer* footer = (bl1_footer *)&buffer[bl1_size - sizeof(bl1_footer)];

    printf("Parsing public key...\n");

    uint8_t nn[0x100];
    reverse_bytes((uint32_t*)nn, (uint32_t*)footer->pubkey_bl1.pubkey_n, sizeof(footer->pubkey_bl1.pubkey_n) / 4);
    BIGNUM *n = BN_bin2bn(nn, sizeof(footer->pubkey_bl1.pubkey_n), NULL);
    uint8_t ee[4];
    reverse_bytes((uint32_t*)ee, (uint32_t*)footer->pubkey_bl1.pubkey_e, sizeof(footer->pubkey_bl1.pubkey_e) / 4);
    BIGNUM *e = BN_bin2bn(ee, sizeof(footer->pubkey_bl1.pubkey_e), NULL);

    if (!n || !e) {
        fprintf(stderr, "Failed to create BIGNUMs for signature verification!\n");
        return 1;
    }

    RSA *rsa = RSA_new();
    if (!rsa) {
        fprintf(stderr, "Failed to create RSA structure!\n");
        return 1;
    }

    if (RSA_set0_key(rsa, n, e, NULL) != 1) {
        fprintf(stderr, "Failed to set RSA key!\n");
        RSA_free(rsa);
        return 1;
    }

    printf("Modulus (N): ");
    BN_print_fp(stdout, RSA_get0_n(rsa));
    printf("\nExponent (E): ");
    BN_print_fp(stdout, RSA_get0_e(rsa));
    printf("\n");


#if 1
    printf("Decrypting signature...\n");
    uint8_t* decrypt_out = nullptr;
    int rsa_size = RSA_size(rsa);

    decrypt_out = malloc(rsa_size);
    if (!decrypt_out) {
        fprintf(stderr, "Memory allocation failed!\n");
        return 1;
    }

    uint8_t sig[0x100];
    reverse_bytes((uint32_t*)sig, (uint32_t*)footer->signature_bl1, sizeof(footer->signature_bl1) / 4);

    memset(decrypt_out, 0, rsa_size);
    int sig_size = RSA_public_decrypt(0x100, sig, decrypt_out, rsa, RSA_NO_PADDING);
    if (sig_size < 0) {
        unsigned long err = ERR_get_error();

        fprintf(stderr, "RSA_public_decrypt failed!\n%s:%s:%s\n", ERR_lib_error_string(err), ERR_func_error_string(err), ERR_reason_error_string(err));
        free(decrypt_out);
        return 1;
    }
    printf("Size: %d\n", sig_size);

    dump_hex(decrypt_out, rsa_size, "Dump:");

    printf("Verifying signature hash...");

    uint32_t orig_chksum = header->chksum;
    header->chksum = 0;
    uint8_t sign_hash[SHA256_DIGEST_LENGTH];
    SHA256(buffer, (uint8_t*)(&footer->pubkey_bl1) - buffer, (char*)sign_hash);
    header->chksum = orig_chksum;

    if (RSA_verify_PKCS1_PSS(rsa, sign_hash, EVP_sha256(), decrypt_out, -2 /*-1 aka 32 works too*/)) {
#else
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey || EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
      fprintf(stderr, "Failed to assign RSA to EVP_PKEY!\n");
      return 1;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
      fprintf(stderr, "Failed to create MD_CTX\n");
      return 1;
    }

    EVP_PKEY_CTX *verify_ctx = NULL;
    if (EVP_DigestVerifyInit(mdctx,
            &verify_ctx,
            EVP_sha256(),
            NULL,
            pkey) != 1) {
      fprintf(stderr, "DigestVerifyInit failed\n");
      return 1;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(verify_ctx, RSA_PKCS1_PSS_PADDING) <= 0)
      return 1;

    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(verify_ctx, -2) <= 0)
      return 1;

    uint32_t orig_chksum = header->chksum;
    header->chksum = 0;
    if (EVP_DigestVerifyUpdate(mdctx, buffer, (uint8_t*)(&footer->pubkey_bl1) - buffer) != 1)
        return 1;
    header->chksum = orig_chksum;

    uint8_t sig[0x100];
    reverse_bytes((uint32_t*)sig, (uint32_t*)footer->signature_bl1, sizeof(footer->signature_bl1) / 4);

    if (EVP_DigestVerifyFinal(mdctx, sig, sizeof(sig)) == 1) {
#endif
        printf("OK!\n");
        return 0;
    } else {
        printf("FAIL!\n");
        return 1;
    }
}

int verify_signature_main(int argc, char *argv[], char* cmd) {
    if (argc < 2) {
        fprintf(stderr, "Usage: TODO!\n", cmd);
        return 1;
    }

    static struct option long_options[] = {
        {"input", required_argument, 0, 'i'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    char* input = NULL;
    char* efuse = NULL;
    optind = 1;

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "i:h",
                                  long_options, &option_index)) != -1) {
        switch (opt) {
        case 'i':
            input = optarg;
            break;
        case 'h':
            fprintf(stderr, "Usage: TODO!\n", cmd);
            return 1;
            break;
        case '?':
            return 1;
            break;
        default:
            fprintf(stderr, "Unknown option\n");
            return 1;
        }
    }

    if (optind < argc) {
        if (input) {
            fprintf(stderr, "Options parse error!\n");
            return 1;
        }

        input = argv[optind++];
    }

    if (optind < argc) {
        fprintf(stderr, "Options parse error!\n");
        return 1;
    }

    if (!input) {
        fprintf(stderr, "No input file!\n");
        return 1;
    }

    uint32_t bl1_size;
    uint8_t* buffer;
    if (open_bl1(input, &buffer, &bl1_size))
        return 1;

    int ret = verify_signature(buffer, bl1_size);

    free(buffer);
    return ret;
    return ret;
}

uint32_t calc_chksum(uint8_t* buffer, uint32_t bl1_size) {
    uint32_t header_hash[SHA256_DIGEST_LENGTH / 4];
    SHA256(&buffer[0x10], bl1_size - 0x10, (char*)header_hash);
    return header_hash[0];
}

int write_header_main(int argc, char *argv[], char* cmd) {
    if (argc == 1) {
        fprintf(stderr, "Usage: TODO!\n", cmd);
//        fprintf(stderr, "Usage: %s <bl1>\n", cmd);
        return 1;
    }

    static struct option long_options[] = {
        {"input", required_argument, 0, 'i'},
        {"output", required_argument, 0, 'o'},
        {"force", no_argument, 0, 'f'},
        {"in-place", no_argument, 0, 'p'},
        {"set-size-only", no_argument, 0, 's'},
        {"update-checksum-only", no_argument, 0, 'c'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    char* input = NULL;
    char* output = NULL;
    uint8_t force_open = 0;
    uint8_t in_place = 0;
    uint8_t set_size_only = 0;
    uint8_t update_checksum_only = 0;
    optind = 1;

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "i:o:fpsch",
                                  long_options, &option_index)) != -1) {
        switch (opt) {
        case 'i':
            input = optarg;
            break;
        case 'o':
            output = optarg;
            break;
        case 'f':
            force_open = 1;
            break;
        case 'p':
            in_place = 1;
            break;
        case 's':
            set_size_only = 1;
            break;
        case 'c':
            update_checksum_only = 1;
            break;
        case 'h':
            fprintf(stderr, "Usage: TODO!\n", cmd);
            return 1;
            break;
        case '?':
            return 1;
            break;
        default:
            fprintf(stderr, "Unknown option\n");
            return 1;
        }
    }

    if (set_size_only && update_checksum_only) {
        fprintf(stderr, "Both set size only, and update checksum only options are set. What are you trying to do here?\n");
        return 1;
    }

    if (optind < argc) {
        if (input) {
            fprintf(stderr, "Options parse error!\n");
            return 1;
        }

        input = argv[optind++];
    }

    if (optind < argc) {
        fprintf(stderr, "Options parse error!\n");
        return 1;
    }

    if (!input) {
        fprintf(stderr, "No input file!\n");
        return 1;
    }
        
    if (!output && !in_place) {
        fprintf(stderr, "No output file!\n");
        return 1;
    }
        
    if (output && in_place) {
        fprintf(stderr, "Both output file and in-place overwrite specified!\n");
        return 1;
    }

    if (in_place)
        output = input;
        

    uint32_t bl1_size;
    uint8_t* buffer;
    if (!update_checksum_only) {
        if (open_bl1_noheader(input, &buffer, &bl1_size, force_open, false, 0))
            return 1;
    } else {
        if (open_bl1(input, &buffer, &bl1_size))
            return 1;
    }

    bl1_head* header = (bl1_head *)buffer;
    header->size_in_blocks = bl1_size >> 9;

    if (!set_size_only) {
          header->chksum = calc_chksum(buffer, bl1_size);
//        uint32_t header_hash[SHA256_DIGEST_LENGTH / 4];
//        SHA256(&buffer[0x10], bl1_size - 0x10, (char*)header_hash);
//        header->chksum = header_hash[0];
    }

    printf("Header created! Blocks: %u, chksum: %08x\n", header->size_in_blocks, header->chksum);

    printf("Writing output!\n");
    if (save_fixlen(output, bl1_size, "BL1", buffer)) {
        free(buffer);
        return 1;
    }

    return 0;
}

int generate_hmac(char* key, uint8_t save_key, uint8_t* pubkey, size_t pubkey_len, uint8_t* out, uint8_t* efuse_out) {
    uint8_t hmac_key[0x20];

    if (key && !save_key) {
        if (open_fixlen(key, 0x20, "HMAC key", hmac_key))
            return 1;
    } else {
        printf("Generating random HMAC key...\n");
        fill_random_array(hmac_key, sizeof(hmac_key));
    }
    dump_hex(hmac_key, sizeof(hmac_key), "HMAC key:");

    if (save_key) {
        if (save_fixlen(key, 0x20, "HMAC key", hmac_key))
            return 1;
    }

    HMAC(EVP_sha256(), hmac_key, sizeof(hmac_key), pubkey, pubkey_len, out, NULL);

    uint8_t efuse_buf[0x20];
    xor_buffers(efuse_buf, hmac_key, out, 0x20);

    dump_hex(efuse_buf, sizeof(efuse_buf), "EFUSE:");

    if (efuse_out) {
        printf("Writing EFUSE!\n");
        if (save_fixlen(efuse_out, 0x20, "EFUSE", efuse_buf))
            return 1;
    }
    return 0;
}

int write_hmac_main(int argc, char *argv[], char* cmd) {
    if (argc == 1) {
        fprintf(stderr, "Usage: TODO!\n", cmd);
//        fprintf(stderr, "Usage: %s <bl1>\n", cmd);
        return 1;
    }

    static uint32_t long_option = 0;
    static struct option long_options[] = {
        {"input", required_argument, 0, 'i'},
        {"output", required_argument, 0, 'o'},
        {"key", required_argument, 0, 'k'},
        {"efuse", required_argument, 0, 'e'},
        {"hmac-value", required_argument, 0, 'v'},
        {"save-key", no_argument, &long_option, 1},
        {"force", no_argument, 0, 'f'},
        {"in-place", no_argument, 0, 'p'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    char* input = NULL;
    char* output = NULL;
    char* key = NULL;
    char* efuse = NULL;
    char* value = NULL;
    uint8_t save_key = 0;
    uint8_t force_open = 0;
    uint8_t in_place = 0;
    optind = 1;

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "i:o:k:e:v:fph",
                                  long_options, &option_index)) != -1) {
        switch (opt) {
        case 0: //long-only option
            switch (long_option) {
                case 1: //save-key
                    save_key = 1;
                    break;
            }
            break;
        case 'i':
            input = optarg;
            break;
        case 'o':
            output = optarg;
            break;
        case 'k':
            key = optarg;
            break;
        case 'e':
            efuse = optarg;
            break;
        case 'v':
            value = optarg;
            break;
        case 'f':
            force_open = 1;
            break;
        case 'p':
            in_place = 1;
            break;
        case 'h':
            fprintf(stderr, "Usage: TODO!\n", cmd);
            return 1;
            break;
        case '?':
            return 1;
            break;
        default:
            fprintf(stderr, "Unknown option\n");
            return 1;
        }
    }

    if (optind < argc) {
        if (input) {
            fprintf(stderr, "Options parse error!\n");
            return 1;
        }

        input = argv[optind++];
    }

    if (optind < argc) {
        fprintf(stderr, "Options parse error!\n");
        return 1;
    }

    if (!input) {
        fprintf(stderr, "No input file!\n");
        return 1;
    }
        
    if (!output && !in_place) {
        fprintf(stderr, "No output file!\n");
        return 1;
    }
        
    if (output && in_place) {
        fprintf(stderr, "Both output file and in-place overwrite specified!\n");
        return 1;
    }
        
    if (!key && save_key) {
        fprintf(stderr, "You need to specify a filename to save a random key to!\n");
        return 1;
    }

    if (value && key) {
        fprintf(stderr, "You cannot specify a HMAC value and a key at the same time!\n");
        return 1;
    }

    if (value && efuse) {
        fprintf(stderr, "You cannot save the calculated EFUSE when specifying a HMAC value directly!\n");
        return 1;
    }

    if (in_place)
        output = input;

    uint32_t bl1_size;
    uint8_t* buffer;

    if (open_bl1(input, &buffer, &bl1_size))
        return 1;

    bl1_footer* footer = (bl1_footer *)&buffer[bl1_size - sizeof(bl1_footer)];

    if (!force_open)
        for (uint32_t i = 0; i < sizeof(footer->hmac_bl1); i++) {
            if (footer->hmac_bl1[i] != 0) {
                fprintf(stderr, "HMAC field not empty!\n");
                free(buffer);
                return 1;
            }
        }


    if (!value) {
        if (generate_hmac(key, save_key, (char*)&footer->pubkey_bl1, sizeof(footer->pubkey_bl1), footer->hmac_bl1, efuse))
            return 1;
    } else {
        if (open_fixlen(value, 0x20, "HMAC value", footer->hmac_bl1))
            return 1;
    }

    printf("Writing output!\n");
    if (save_fixlen(output, bl1_size, "BL1", buffer)) {
        free(buffer);
        return 1;
    }

    return 0;
}

int generate_hmac_main(int argc, char *argv[], char* cmd) {
    if (argc == 1) {
        fprintf(stderr, "Usage: TODO!\n", cmd);
        return 1;
    }

    static uint32_t long_option = 0;
    static struct option long_options[] = {
        {"public-key", required_argument, 0, 'p'},
        {"output", required_argument, 0, 'o'},
        {"key", required_argument, 0, 'k'},
        {"efuse", required_argument, 0, 'e'},
        {"save-key", no_argument, &long_option, 1},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    char* public_key = NULL;
    char* output = NULL;
    char* key = NULL;
    char* efuse = NULL;
    uint8_t save_key = 0;
    optind = 1;

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "p:o:k:e:h",
                                  long_options, &option_index)) != -1) {
        switch (opt) {
        case 0: //long-only option
            switch (long_option) {
                case 1: //save-key
                    save_key = 1;
                    break;
            }
            break;
        case 'p':
            public_key = optarg;
            break;
        case 'o':
            output = optarg;
            break;
        case 'k':
            key = optarg;
            break;
        case 'e':
            efuse = optarg;
            break;
        case 'h':
            fprintf(stderr, "Usage: TODO!\n", cmd);
            return 1;
            break;
        case '?':
            return 1;
            break;
        default:
            fprintf(stderr, "Unknown option\n");
            return 1;
        }
    }

    if (optind < argc) {
        fprintf(stderr, "Options parse error!\n");
        return 1;
    }

    if (!efuse) {
        fprintf(stderr, "You should probably save your efuse!\n");
        return 1;
    }
        
    if (!public_key) {
        fprintf(stderr, "No public key!\n");
        return 1;
    }

    if (!output) {
        fprintf(stderr, "No output file!\n");
        return 1;
    }
        
    if (!key && save_key) {
        fprintf(stderr, "You need to specify a filename to save a random key to!\n");
        return 1;
    }

    printf("Loading public key...\n");

    samsung_pubkey pubkey;
    if (open_fixlen(public_key, sizeof(samsung_pubkey), "public key", (uint8_t*)&pubkey)) {
        return 1;
    }

    uint8_t hmac[0x20];
    if (generate_hmac(key, save_key, (char*)&pubkey, sizeof(pubkey), hmac, efuse))
        return 1;

    printf("Writing HMAC!\n");
    if (save_fixlen(output, 0x20, "HMAC", hmac)) {
        return 1;
    }
    return 0;
}


int generate_key_main(int argc, char *argv[], char* cmd) {
    if (argc < 2) {
        fprintf(stderr, "Usage: TODO!\n", cmd);
        return 1;
    }

    static struct option long_options[] = {
        {"private", required_argument, 0, 'r'},
        {"public", required_argument, 0, 'u'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    char* privkey_filename = NULL;
    char* pubkey_filename = NULL;
    optind = 1;

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "r:u:h",
                                  long_options, &option_index)) != -1) {
        switch (opt) {
        case 'r':
            privkey_filename = optarg;
            break;
        case 'u':
            pubkey_filename = optarg;
            break;
        case 'h':
            fprintf(stderr, "Usage: TODO!\n", cmd);
            return 1;
            break;
        case '?':
            return 1;
            break;
        default:
            fprintf(stderr, "Unknown option\n");
            return 1;
        }
    }

    if (optind < argc) {
        fprintf(stderr, "Options parse error!\n");
        return 1;
    }

    if (!privkey_filename) {
        fprintf(stderr, "No private key output!\n");
        return 1;
    }
        
    if (!pubkey_filename) {
        fprintf(stderr, "No public key output!\n");
        return 1;
    }


    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
//    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);//EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!ctx) {
        fprintf(stderr, "EVP_PKEY_CTX creation failed!\n");
        return 1;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen_init failed!\n");
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }

    BIGNUM *pubexp = BN_new();
    if (!pubexp) {
        fprintf(stderr, "BN creation failed!\n");
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }

//    BN_set_word(pubexp, RSA_F4); // 65537
    if (!BN_set_word(pubexp, 3)) {
        fprintf(stderr, "BN_set_word failed!\n");
        EVP_PKEY_CTX_free(ctx);
        BN_free(pubexp);
        return 1;
    }

    //if (EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, pubexp) <= 0) {
    if (EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, pubexp) <= 0) {
        fprintf(stderr, "Setting public key exponent failed!\n");
        EVP_PKEY_CTX_free(ctx);
        BN_free(pubexp);
        return 1;
    }
//it should now    //pubexp shouldn't be touched after this in theory
    BN_free(pubexp);

    if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen_init failed!\n");
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }

    EVP_PKEY_CTX_free(ctx);

    //Private key
    printf("Writing private key file...\n");
    FILE *fp = fopen(privkey_filename, "wb");
    if (!fp) {
        fprintf(stderr, "Error while opening private key file for output!\n");
        EVP_PKEY_free(pkey);
        return 1;
    }

    if (!PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "Failed to write private key!\n");
        EVP_PKEY_free(pkey);
        return 1;
    }

    fclose(fp);

    //Public key
    printf("Writing public key file...\n");
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    uint8_t n_be[0x100];
    uint8_t e_be[0x4];

    if ((EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n) <= 0) ||
        (BN_bn2binpad(n, n_be, 0x100) <= 0)) {
        fprintf(stderr, "Getting pubkey N failed!\n");
        EVP_PKEY_free(pkey);
        return 1;
    }

    if ((EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e) <= 0) ||
        (BN_bn2binpad(e, e_be, 0x4) <= 0)) {
        fprintf(stderr, "Getting pubkey E failed!\n");
        EVP_PKEY_free(pkey);
        return 1;
    }

    EVP_PKEY_free(pkey);

    printf("Pubkey:\n");
    printf("Modulus (N): ");
    BN_print_fp(stdout, n);
    printf("\nExponent (E): ");
    BN_print_fp(stdout, e);
    printf("\n");

    BN_free(n);
    BN_free(e);

    samsung_pubkey pubkey;
    pubkey.pubkey_n_len = 0x100;
    reverse_bytes((uint32_t*)pubkey.pubkey_n, (uint32_t*)n_be, pubkey.pubkey_n_len / 4);
    pubkey.pubkey_e_len = 0x4;
    reverse_bytes((uint32_t*)pubkey.pubkey_e, (uint32_t*)e_be, pubkey.pubkey_e_len / 4);

    if (save_fixlen(pubkey_filename, sizeof(samsung_pubkey), "public key", (uint8_t*)&pubkey)) {
        return 1;
    }

    return 0;
}

int write_pubkey_main(int argc, char *argv[], char* cmd) {
    if (argc == 1) {
        fprintf(stderr, "Usage: TODO!\n", cmd);
        return 1;
    }

    static struct option long_options[] = {
        {"input", required_argument, 0, 'i'},
        {"output", required_argument, 0, 'o'},
        {"pubkey", required_argument, 0, 'u'},
        {"force", no_argument, 0, 'f'},
        {"in-place", no_argument, 0, 'p'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    char* input = NULL;
    char* output = NULL;
    char* pubkey_file = NULL;
    uint8_t force_open = 0;
    uint8_t in_place = 0;
    optind = 1;

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "i:o:u:fph",
                                  long_options, &option_index)) != -1) {
        switch (opt) {
        case 'i':
            input = optarg;
            break;
        case 'o':
            output = optarg;
            break;
        case 'u':
            pubkey_file = optarg;
            break;
        case 'f':
            force_open = 1;
            break;
        case 'p':
            in_place = 1;
            break;
        case 'h':
            fprintf(stderr, "Usage: TODO!\n", cmd);
            return 1;
            break;
        case '?':
            return 1;
            break;
        default:
            fprintf(stderr, "Unknown option\n");
            return 1;
        }
    }

    if (optind < argc) {
        if (input) {
            fprintf(stderr, "Options parse error!\n");
            return 1;
        }

        input = argv[optind++];
    }

    if (optind < argc) {
        fprintf(stderr, "Options parse error!\n");
        return 1;
    }

    if (!input) {
        fprintf(stderr, "No input file!\n");
        return 1;
    }
        
    if (!output && !in_place) {
        fprintf(stderr, "No output file!\n");
        return 1;
    }
        
    if (output && in_place) {
        fprintf(stderr, "Both output file and in-place overwrite specified!\n");
        return 1;
    }

    if (!pubkey_file) {
        fprintf(stderr, "No public key specified!\n");
        return 1;
    }
        
    if (in_place)
        output = input;

    uint32_t bl1_size;
    uint8_t* buffer;

    printf("Opening input...\n");
    if (open_bl1(input, &buffer, &bl1_size))
        return 1;

    bl1_footer* footer = (bl1_footer *)&buffer[bl1_size - sizeof(bl1_footer)];

    if (!force_open)
        for (uint32_t i = 0; i < sizeof(footer->pubkey_bl1); i++) {
            if (((uint8_t*)(&footer->pubkey_bl1))[i] != 0) {
                fprintf(stderr, "Public key not empty!\n");
                free(buffer);
                return 1;
            }
        }

    printf("Opening public key...\n");
    if (open_fixlen(pubkey_file, sizeof(footer->pubkey_bl1), "public key", (uint8_t*)&footer->pubkey_bl1)) {
        return 1;
    }

    printf("Writing output...\n");
    if (save_fixlen(output, bl1_size, "BL1", buffer)) {
        free(buffer);
        return 1;
    }
}

int sign(uint8_t* buffer, uint32_t bl1_size, char* privkey_file) {
    bl1_head* header = (bl1_head *)buffer;
    bl1_footer* footer = (bl1_footer *)&buffer[bl1_size - sizeof(bl1_footer)];

    printf("Opening private key...\n");
    FILE *privkey = fopen(privkey_file, "rb");
    if (!privkey) {
        perror("Failed to open private key");
        return 1;
    }

    EVP_PKEY *pkey = PEM_read_PrivateKey(privkey, NULL, NULL, NULL);
    if (!pkey) {
        fprintf(stderr, "Failed to read private key\n");
        fclose(privkey);
        return 1;
    }
    fclose(privkey);

#if 0
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;

    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n) <= 0) {
        fprintf(stderr, "Getting pubkey N failed!\n");
        EVP_PKEY_free(pkey);
        return 1;
    }

    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e) <= 0) {
        fprintf(stderr, "Getting pubkey E failed!\n");
        EVP_PKEY_free(pkey);
        return 1;
    }

    printf("Pubkey:\n");
    printf("Modulus (N): ");
    BN_print_fp(stdout, n);
    printf("\nExponent (E): ");
    BN_print_fp(stdout, e);
    printf("\n");

    BN_free(n);
    BN_free(e);
#endif

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "EVP_MD_CTX_new failed!\n");
        return 1;
    }

    EVP_PKEY_CTX *pkctx = NULL;
    if (EVP_DigestSignInit(mdctx,
                           &pkctx,
                           EVP_sha256(),
                           NULL,
                           pkey) != 1) {
        fprintf(stderr, "EVP_DigestSignInit failed!\n");
        return 1;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(pkctx,
                                     RSA_PKCS1_PSS_PADDING) <= 0) {
        fprintf(stderr, "Setting RSA_PKCS1_PSS_PADDING failed!\n");
        return 1;
    }

    //TODO test
    //if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkctx, -2) <= 0) {
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkctx, 32) <= 0) {
        fprintf(stderr, "Setting salt length failed!\n");
        return 1;
    }

    printf("Signing...\n");
    //Uhh... this will become invalid anyways...
    uint32_t orig_chksum = header->chksum;
    header->chksum = 0;

    if (EVP_DigestSignUpdate(mdctx, buffer, (uint8_t*)(&footer->pubkey_bl1) - buffer) != 1) {
        fprintf(stderr, "SignUpdate failed!\n");
        return 1;
    }

    header->chksum = orig_chksum;

    uint8_t sig[sizeof(footer->signature_bl1)];
    size_t sign_size = sizeof(footer->signature_bl1);

    if (EVP_DigestSignFinal(mdctx, sig, &sign_size) != 1 || sign_size != sizeof(footer->signature_bl1)) {
        fprintf(stderr, "SignFinal failed!\n");
        return 1;
    }
    reverse_bytes((uint32_t*)footer->signature_bl1, (uint32_t*)sig, sizeof(footer->signature_bl1) / 4);
    return 0;
}

int sign_main(int argc, char *argv[], char* cmd) {
    if (argc == 1) {
        fprintf(stderr, "Usage: TODO!\n", cmd);
        return 1;
    }

    static struct option long_options[] = {
        {"input", required_argument, 0, 'i'},
        {"output", required_argument, 0, 'o'},
        {"privkey", required_argument, 0, 'r'},
        {"force", no_argument, 0, 'f'},
        {"in-place", no_argument, 0, 'p'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    char* input = NULL;
    char* output = NULL;
    char* privkey_file = NULL;
    uint8_t force_open = 0;
    uint8_t in_place = 0;
    optind = 1;

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "i:o:r:fph",
                                  long_options, &option_index)) != -1) {
        switch (opt) {
        case 'i':
            input = optarg;
            break;
        case 'o':
            output = optarg;
            break;
        case 'r':
            privkey_file = optarg;
            break;
        case 'f':
            force_open = 1;
            break;
        case 'p':
            in_place = 1;
            break;
        case 'h':
            fprintf(stderr, "Usage: TODO!\n", cmd);
            return 1;
            break;
        case '?':
            return 1;
            break;
        default:
            fprintf(stderr, "Unknown option\n");
            return 1;
        }
    }

    if (optind < argc) {
        if (input) {
            fprintf(stderr, "Options parse error!\n");
            return 1;
        }

        input = argv[optind++];
    }

    if (optind < argc) {
        fprintf(stderr, "Options parse error!\n");
        return 1;
    }

    if (!input) {
        fprintf(stderr, "No input file!\n");
        return 1;
    }
        
    if (!output && !in_place) {
        fprintf(stderr, "No output file!\n");
        return 1;
    }
        
    if (output && in_place) {
        fprintf(stderr, "Both output file and in-place overwrite specified!\n");
        return 1;
    }

    if (!privkey_file) {
        fprintf(stderr, "No private key specified!\n");
        return 1;
    }
        
    if (in_place)
        output = input;

    uint32_t bl1_size;
    uint8_t* buffer;

    printf("Opening input...\n");
    if (open_bl1(input, &buffer, &bl1_size))
        return 1;

    bl1_head* header = (bl1_head *)buffer;
    bl1_footer* footer = (bl1_footer *)&buffer[bl1_size - sizeof(bl1_footer)];

    if (!force_open)
        for (uint32_t i = 0; i < sizeof(footer->signature_bl1); i++) {
            if (((uint8_t*)(&footer->signature_bl1))[i] != 0) {
                fprintf(stderr, "Signature not empty!\n");
                free(buffer);
                return 1;
            }
        }

    if (sign(buffer, bl1_size, privkey_file)) {
        free(buffer);
        return 1;
    }

    printf("Writing output...\n");
    if (save_fixlen(output, bl1_size, "BL1", buffer)) {
        free(buffer);
        return 1;
    }

    free(buffer);
}

int build_main(int argc, char *argv[], char* cmd) {
    if (argc == 1) {
        fprintf(stderr, "Usage: TODO!\n", cmd);
        return 1;
    }

    static uint32_t long_option = 0;
    static struct option long_options[] = {
        {"input", required_argument, 0, 'i'},
        {"output", required_argument, 0, 'o'},
        {"privkey", required_argument, 0, 'r'},
        {"pubkey", required_argument, 0, 'u'},
        {"hmac", required_argument, 0, 'm'},
        {"id1", required_argument, &long_option, 1},
        {"id2", required_argument, &long_option, 2},
        {"pubkey_bl31", required_argument, &long_option, 3},
        {"force_size", required_argument, &long_option, 4},
        {"force", no_argument, 0, 'f'},
        {"in-place", no_argument, 0, 'p'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    char* input = NULL;
    char* output = NULL;
    char* privkey_file = NULL;
    char* pubkey_file = NULL;
    char* hmac_file = NULL;
    uint8_t force_open = 0;
    uint8_t in_place = 0;
    uint16_t id1 = 0;
    uint16_t id2 = 0;
    char* pubkey_bl31_file = NULL;
    uint32_t force_size = 0;
    optind = 1;

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "i:o:r:u:m:fph",
                                  long_options, &option_index)) != -1) {
        switch (opt) {
        case 0: //long-only option
            switch (long_option) {
                case 1: //ID1
                    id1 = strtoul(optarg, NULL, 0);
                    break;
                case 2: //ID2
                    id2 = strtoul(optarg, NULL, 0);
                    break;
                case 3: //BL31 pubkey
                    pubkey_bl31_file = optarg;
                    break;
                case 4: //forced size
                    force_size = strtoul(optarg, NULL, 0);
                    break;
            }
            break;
        case 'i':
            input = optarg;
            break;
        case 'o':
            output = optarg;
            break;
        case 'r':
            privkey_file = optarg;
            break;
        case 'u':
            pubkey_file = optarg;
            break;
        case 'm':
            hmac_file = optarg;
            break;
        case 'f':
            force_open = 1;
            break;
        case 'p':
            in_place = 1;
            break;
        case 'h':
            fprintf(stderr, "Usage: TODO!\n", cmd);
            return 1;
            break;
        case '?':
            return 1;
            break;
        default:
            fprintf(stderr, "Unknown option\n");
            return 1;
        }
    }

    if (optind < argc) {
        if (input) {
            fprintf(stderr, "Options parse error!\n");
            return 1;
        }

        input = argv[optind++];
    }

    if (optind < argc) {
        fprintf(stderr, "Options parse error!\n");
        return 1;
    }

    if (!input) {
        fprintf(stderr, "No input file!\n");
        return 1;
    }
        
    if (!output && !in_place) {
        fprintf(stderr, "No output file!\n");
        return 1;
    }
        
    if (output && in_place) {
        fprintf(stderr, "Both output file and in-place overwrite specified!\n");
        return 1;
    }

    if (!privkey_file) {
        fprintf(stderr, "No private key specified!\n");
        return 1;
    }

    if (!pubkey_file) {
        fprintf(stderr, "No private key specified!\n");
        return 1;
    }

    if (!hmac_file) {
        fprintf(stderr, "No HMAC specified!\n");
        return 1;
    }

#if 0
    //For now, we expect a BL1 with final size, with chksum, pubkey, hmac, sigsize, and signature zeroed out
    uint32_t bl1_size;
    uint8_t* buffer;
    if (open_bl1(input, &buffer, &bl1_size))
        return 1;
#else
    //We expect a BL1 with header zeroed out, and footer not included in the file.
    uint32_t bl1_size;
    uint8_t* buffer;
    if (open_bl1_noheader(input, &buffer, &bl1_size, force_open, true, force_size))
        return 1;
#endif

    bl1_head* header = (bl1_head *)buffer;
    bl1_footer* footer = (bl1_footer *)&buffer[bl1_size - sizeof(bl1_footer)];

#if 0
    if (!force_open) {
        if (header->chksum != 0) {
            fprintf(stderr, "Checksum not empty!\n");
            free(buffer);
            return 1;
        }
        for (uint32_t i = 0; i < sizeof(footer->hmac_bl1); i++) {
            if (footer->hmac_bl1[i] != 0) {
                fprintf(stderr, "HMAC field not empty!\n");
                free(buffer);
                return 1;
            }
        }
        for (uint32_t i = 0; i < sizeof(footer->pubkey_bl1); i++) {
            if (((uint8_t*)(&footer->pubkey_bl1))[i] != 0) {
                fprintf(stderr, "Public key not empty!\n");
                free(buffer);
                return 1;
            }
        }
        if (footer->sigsize != 0) {
            fprintf(stderr, "Sigsize not empty!\n");
            free(buffer);
            return 1;
        }
        for (uint32_t i = 0; i < sizeof(footer->signature_bl1); i++) {
            if (((uint8_t*)(&footer->signature_bl1))[i] != 0) {
                fprintf(stderr, "Signature not empty!\n");
                free(buffer);
                return 1;
            }
        }
        if (footer->id1 || footer->id2) {
            fprintf(stderr, "The ID fields are not empty!\n");
            free(buffer);
            return 1;
        }
        if (pubkey_bl31_file)
            for (uint32_t i = 0; i < sizeof(footer->pubkey_bl31); i++) {
                if (((uint8_t*)(&footer->pubkey_bl31))[i] != 0) {
                    fprintf(stderr, "BL31 public key not empty!\n");
                    free(buffer);
                    return 1;
                }
            }
    }
#endif

    printf("Setting ID fields...\n");
    footer->id1 = id1;
    footer->id2 = id2;

    if (pubkey_bl31_file) {
        printf("Adding BL31 public key...\n");
        if (open_fixlen(pubkey_bl31_file, sizeof(footer->pubkey_bl31), "BL31 public key", (uint8_t*)&footer->pubkey_bl31)) {
            free(buffer);
            return 1;
        }
    }

    //could be generated from private key too! maybe do that?
    printf("Adding public key...\n");
    if (open_fixlen(pubkey_file, sizeof(footer->pubkey_bl1), "public key", (uint8_t*)&footer->pubkey_bl1)) {
        free(buffer);
        return 1;
    }

    printf("Adding HMAC...\n");
    if (open_fixlen(hmac_file, sizeof(footer->hmac_bl1), "HMAC value", footer->hmac_bl1)) {
        free(buffer);
        return 1;
    }

    footer->sigsize = 0x100;

    if (sign(buffer, bl1_size, privkey_file)) {
        free(buffer);
        return 1;
    }

    printf("Calculating checksum...\n");
    header->chksum = calc_chksum(buffer, bl1_size);

    printf("Writing output...\n");
    if (save_fixlen(output, bl1_size, "BL1", buffer)) {
        free(buffer);
        return 1;
    }
}

int verify_main2(int argc, char *argv[]) {
    if (argc != 2 && argc != 3) {
        fprintf(stderr, "Usage: %s <bl1> [efuse]\n", argv[0]);
        return 1;
    }

    uint32_t bl1_size;
    uint8_t* buffer;

    if (open_bl1(argv[1], &buffer, &bl1_size))
        return 1;

    uint8_t efuse_buf[0x20];
    if (argc == 3) {
        if (open_efuse(argv[2], efuse_buf))
            return 1;
    }

    bl1_head* header = (bl1_head *)buffer;
    bl1_footer* footer = (bl1_footer *)&buffer[bl1_size - sizeof(bl1_footer)];

    verify_checksum(buffer, bl1_size, header);

    printf("Reading footer:\n");
    printf("Signer version: %u\n", footer->signer_version);
    printf("AP info: %c%c%c%c\n", footer->ap_info[0], footer->ap_info[1], footer->ap_info[2], footer->ap_info[3]);
    if (*((uint32_t*)footer->ap_info) != 0x49534c53 /*SLSI*/) {
        printf("Note: AP info not SLSI!\n");
    }


    struct tm *tm = gmtime(&footer->date);
    if (!tm) {
        perror("gmtime failed");
        return 1;
    }

    char human_date[64];
    if (strftime(human_date, sizeof(human_date), "%Y-%m-%d %H:%M:%S", tm) == 0) {
        fprintf(stderr, "strftime failed\n");
        return 1;
    }

    printf("Build date: %s\n", human_date);
    printf("RP count: %u\n", footer->rp_count);
    printf("Signing Type: %u\n", footer->sign_type);
    if (footer->sign_type != 0) {
        fprintf(stderr, "Expected signing type 0!\n");
        return 1;
    }

    printf("ID: 0x%04x 0x%04x\n", footer->id1, footer->id2);
    printf("Signature size: 0x%02x\n", footer->sigsize);
    if (footer->sigsize != 0x100) {
        fprintf(stderr, "Expected signature size 0x100!\n");
        return 1;
    }


    if (argc == 3) {
        verify_pubkey(footer, efuse_buf);
    } else {
        printf("Skip checking BL1 pubkey, because efuse is not set!\n");
    }

    verify_signature(buffer, bl1_size);
    return 0;
}

int get_cmd_subcmd(char* cmd, char* subcmd, char** cmd_subcmd) {
    int cmd_subcmd_len = snprintf(NULL, 0, "%s %s", cmd, subcmd);
    if (cmd_subcmd_len <= 0) {
        fprintf(stderr, "%s: Fatal option parse error\n", cmd);
        return 1;
    }
    *cmd_subcmd = malloc(cmd_subcmd_len+1);
    snprintf(*cmd_subcmd, cmd_subcmd_len+1, "%s %s", cmd, subcmd);
    return 0;
}

int verify_main(int argc, char *argv[], char* cmd) {
    if (argc < 2) {
        printf("OpenExyBootchain BL1Tool\n"
               "verify subcommand\n"
               "Available commands:\n"
               "\tchecksum: verify BL1 header checksum\n"
               "\tpubkey: verify BL1 pubkey using HMAC and efuse key\n"
               "\tsignature: verify BL1 signature using the pubkey embedded in it\n"
                );
        return 1;
    }

    char* cmd_subcmd;
    if (get_cmd_subcmd(cmd, argv[1], &cmd_subcmd))
        return 1;

    if (strcmp(argv[1], "checksum") == 0)
        return verify_checksum_main(argc - 1, argv + 1, cmd_subcmd);

    if (strcmp(argv[1], "pubkey") == 0)
        return verify_pubkey_main(argc - 1, argv + 1, cmd_subcmd);

    if (strcmp(argv[1], "signature") == 0)
        return verify_signature_main(argc - 1, argv + 1, cmd_subcmd);

    if (strcmp(argv[1], "test") == 0)
        return verify_main2(argc - 1, argv + 1);

    fprintf(stderr, "%s: Unknown command: %s\n", cmd, argv[1]);
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("OpenExyBootchain BL1Tool\n"
               "Available commands:\n"
               "\tverify: options to verify BL1\n"
               "\twrite_header: write a valid BL1 header to file, including size and checksum\n"
               "\twrite_hmac: asdasdasdasgasjgjgsaéljasgljlésgajasgélsagjaésljgasélgasjéééé\n"
                );
        return 1;
    }

    //Random generation setup
    srand(time(NULL));

    char* cmd_subcmd;
    if (get_cmd_subcmd(argv[0], argv[1], &cmd_subcmd))
        return 1;

    const struct command cmds[] = {
        {"verify", verify_main},
        {"write_header", write_header_main},
        {"write_hmac", write_hmac_main},
        {"write_pubkey", write_pubkey_main},
        {"generate_key", generate_key_main},
        {"generate_hmac", generate_hmac_main},
        {"sign", sign_main},
        {"build", build_main},
    };

    for (int i = 0; i < sizeof(cmds)/sizeof(struct command); i++) {
        if (strcmp(argv[1], cmds[i].name) == 0)
            return cmds[i].func(argc - 1, argv + 1, cmd_subcmd);
    }

    fprintf(stderr, "%s: Unknown command: %s\n", argv[0], argv[1]);
    return 1;
}

