#pragma once
#ifndef _DH_API_H_
#define _DH_API_H_

//编码函数，out_data和out_len为输出数据和长度，其余均为输入数据

int dh_encode(double width, double height, unsigned char* iv, char* vkekType, char* vkekId, char* evk, char* mode, int position, int enlength, char* meta_sign,
    char* ext_data, char* ext_sign, unsigned char** out_data, int* out_len);

//宽度解码函数

double dh_decode_width(unsigned char* input_data, int input_len, double* output);

//高度解码函数

double dh_decode_height(unsigned char* input_data, int input_len, double* output);

//数据解码函数，output_data要开辟足够大小的空间来存放，output_len是空间大小的值

int dh_decode_ext_data(unsigned char* input_data, int input_len, unsigned char* output_data, int* output_len);

#endif
