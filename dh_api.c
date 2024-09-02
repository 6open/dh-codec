#include <stdio.h>
#include <string.h>
#include "tlv_box.h"
#include "dh_api.h"

#define DATA_LEN        256
#define SIGN_LEN        64
#define IV_LEN          16

#define uchar           unsigned char
#define MAGIC           "DHEP"



enum ALG_TYPE {
    AES256_OFB_NOPADDING = 0,
    AES256_OFB_NOPADDING_SHA256withRSA = 1,
    AES256_CTR = 2,
    AES256_CTR_SHA256withRSA = 3,
    SM4_OFB_NOPADDING = 4,
    SM4_OFB_NOPADDING_SM3withSM2 = 5,
    SM4_CTR = 6,
    SM4_CTR_SM3withSM2 = 7,
    AES128_GCM = 8
};

enum MSG_TAG {
    TAG_META = 0,
    TAG_MAGIC,
    TAG_LENGTH,
    TAG_WIDTH,
    TAG_HEIGHT,
    TAG_TYPE,
    TAG_IV,
    TAG_VKEKTYPE,
    TAG_VKEKID,
    TAG_EVK,
    TAG_MODE,
    TAG_MCONTENT_DATA,
    TAG_MCONTENT_POSITION,
    TAG_MCONTENT_ENLENGTH,
    TAG_META_SIGN,

    TAG_EXT = 100,
    TAG_EXT_DATA,
    TAG_EXT_SIGN,
};

void printf_hex(unsigned char* data, int length) {
    for (int i = 0; i < length; i++) {
        printf("%02x ", data[i]);
    }
}


int dh_encode(double width, double height, unsigned char* iv, char* vkekType, char* vkekId, char* evk, char* mode, int position, int enlength, char* meta_sign,
    char* ext_data, char* ext_sign, unsigned char** out_data, int* out_len) {
    
    tlv_box_t* dh_box = tlv_box_create();
    tlv_box_t* meta_box = tlv_box_create();
    tlv_box_t* mc_content_box = tlv_box_create();
    tlv_box_t* ext_box = tlv_box_create();
    printf("\nLK_test4\n");
    int magic_data;
    memcpy(&magic_data, MAGIC, 4);

    tlv_box_put_int(meta_box, TAG_MAGIC, magic_data);

    tlv_box_put_double(meta_box, TAG_WIDTH, width);
    tlv_box_put_double(meta_box, TAG_HEIGHT, height);

    char type_data = AES128_GCM;

    tlv_box_put_char(meta_box, TAG_TYPE, type_data);
    tlv_box_put_bytes(meta_box, TAG_IV, iv, IV_LEN);
    tlv_box_put_string(meta_box, TAG_VKEKTYPE, vkekType);
    tlv_box_put_string(meta_box, TAG_VKEKID, vkekId);
    tlv_box_put_string(meta_box, TAG_EVK, evk);
    tlv_box_put_string(meta_box, TAG_MODE, mode);

    tlv_box_put_object(meta_box, TAG_MCONTENT_DATA, mc_content_box);
    tlv_box_put_int(mc_content_box, TAG_MCONTENT_POSITION, position);
    tlv_box_put_int(mc_content_box, TAG_MCONTENT_ENLENGTH, enlength);
    tlv_box_put_bytes(meta_box, TAG_META_SIGN, meta_sign, SIGN_LEN);

    if (tlv_box_serialize(meta_box) != 0) {
        printf("boxes serialize failed !\n");
        return -1;
    }
    tlv_box_put_object(dh_box, TAG_META, meta_box);

    tlv_box_put_bytes(ext_box, TAG_EXT_DATA, ext_data, enlength);
    tlv_box_put_bytes(ext_box, TAG_EXT_SIGN, ext_sign, SIGN_LEN);
    if (tlv_box_serialize(ext_box) != 0) {
        printf("boxes serialize failed !\n");
        return -1;
    }
    tlv_box_put_object(dh_box, TAG_EXT, ext_box);

    if (tlv_box_serialize(dh_box) != 0) {
        printf("boxes serialize failed !\n");
        return -1;
    }

    *out_data = tlv_box_get_buffer(dh_box);
    *out_len = tlv_box_get_size(dh_box);
    printf_hex(tlv_box_get_buffer(dh_box), tlv_box_get_size(dh_box));
    
    return tlv_box_get_buffer(dh_box);
    
    return 1;
}


double dh_decode_width(unsigned char* input_data, int input_len, double* output) {

    tlv_box_t* dh_box = tlv_box_parse(input_data, input_len);
    tlv_box_t* mete_box;
    if (tlv_box_get_object(dh_box, TAG_META, &mete_box) != 0) {
        printf("tlv_box_get_object failed !\n");
        return -1;
    }
    
    if (tlv_box_get_double(mete_box, TAG_WIDTH, output) != 0) {
        printf("tlv_box_get_char failed !\n");
        return -1;
    }
    printf("\nwidth : %f\n", *output);
    return 0;
}


double dh_decode_height(unsigned char* input_data, int input_len, double* output) {

    tlv_box_t* dh_box = tlv_box_parse(input_data, input_len);
    tlv_box_t* mete_box;
    if (tlv_box_get_object(dh_box, TAG_META, &mete_box) != 0) {
        printf("tlv_box_get_object failed !\n");
        return -1;
    }

    if (tlv_box_get_double(mete_box, TAG_HEIGHT, output) != 0) {
        printf("tlv_box_get_char failed !\n");
        return -1;
    }
    return 0;
}


int dh_decode_ext_data(unsigned char* input_data, int input_len, unsigned char* output_data, int* output_len) {

    tlv_box_t* dh_box = tlv_box_parse(input_data, input_len);
    tlv_box_t* ext_box;
    if (tlv_box_get_object(dh_box, TAG_EXT, &ext_box) != 0) {
        printf("tlv_box_get_object failed !\n");
        return -1;
    }

    if (tlv_box_get_bytes(ext_box, TAG_EXT_DATA, output_data, output_len) != 0) {
        printf("\nget data failed !\n");
        return -1;
    }

    return 0;
}

tlv_box_t* dh_decode(unsigned char* input_data, double width, double high, unsigned char* iv, char* vkekType, char* vkekId, char* evk, char* mode, int position, int enlength, char* meta_sign,
    char* ext_data, char* ext_sign) {

}
