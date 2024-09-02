/*
 *  COPYRIGHT NOTICE  
 *  Copyright (C) 2015, Jhuster, All Rights Reserved
 *  Author: Jhuster(lujun.hust@gmail.com)
 *  
 *  https://github.com/Jhuster/TLV
 *   
 *  This library is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published
 *  by the Free Software Foundation; either version 2.1 of the License, 
 *  or (at your option) any later version.
 */
#include <stdio.h>
#include <string.h>
#include "tlv_box.h"
#include "dh_api.h"
#define LOG(format,...) printf(format, ##__VA_ARGS__)

int main(int argc, char const *argv[])
{
    unsigned char iv[16] = {1};
    memset(iv, 1, 16);
    unsigned char meta_sign[64] = {2};
    memset(meta_sign, 2, 64);
    unsigned char ext_sign[64] = {3};
    memset(ext_sign, 3, 64);
    unsigned char* seria_data;
    int out_len;
    dh_encode(1.1, 2.2, iv, "aaaaaa", "vkekId", "evk", "mode", 0xf, sizeof("ext_data"), meta_sign, "ext_data", ext_sign, &seria_data, &out_len);  

    double width = 0;
    dh_decode_width(seria_data, out_len, &width);   
    printf("\n%f\n", width);
    double height = 0;
    dh_decode_height(seria_data, out_len, &height);   
    printf("\n%f\n", height);
    unsigned char output_data[128] = {0};
    int output_len = 128;
    dh_decode_ext_data(seria_data, out_len, output_data, &output_len);
    printf("\n%s\n", output_data, &output_len);
    
    return 0;
}
