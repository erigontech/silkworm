/********************************************************************\
 *
 *      FILE:     rmd160.h
 *
 *      CONTENTS: Header file for a sample C-implementation of the
 *                RIPEMD-160 hash-function. 
 *      TARGET:   any computer with an ANSI C compiler
 *
 *      AUTHOR:   Antoon Bosselaers, ESAT-COSIC
 *      DATE:     1 March 1996
 *      MODIFIED: 11 December 2020 by Andrew Ashikhmin for Silkworm    
 *      VERSION:  1.0 + Silkworm modifications
 *
 *      Copyright (c) 1996 Katholieke Universiteit Leuven
 *
 *      Permission is hereby granted, free of charge, to any person
 *      obtaining a copy of this software and associated documentation
 *      files (the "Software"), to deal in the Software without restriction,
 *      including without limitation the rights to use, copy, modify, merge,
 *      publish, distribute, sublicense, and/or sell copies of the Software,
 *      and to permit persons to whom the Software is furnished to do so,
 *      subject to the following conditions:
 *
 *      The above copyright notice and this permission notice shall be 
 *      included in all copies or substantial portions of the Software.
 *
 *      THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 *      EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF 
 *      MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
 *      IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY 
 *      CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
 *      TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 *      SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
\********************************************************************/

#ifndef  SILKWORM_CRYPTO_RMD160_H_
#define  SILKWORM_CRYPTO_RMD160_H_

#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

/********************************************************************/

/* typedef 8 and 32 bit types, resp.  */
/* adapt these, if necessary, 
   for your operating system and compiler */
typedef    uint8_t        byte;
typedef    uint32_t       dword;

/* if this line causes a compiler error, 
   adapt the defintion of dword above */
typedef int the_correct_size_was_chosen [sizeof (dword) == 4? 1: -1];

/********************************************************************/

/* function prototypes */

void rmd160_init(dword *MDbuf);
/*
 *  initializes MDbuffer to "magic constants"
 */

void rmd160_compress(dword *MDbuf, dword *X);
/*
 *  the compression function.
 *  transforms MDbuf using message bytes X[0] through X[15]
 */

void rmd160_finish(dword *MDbuf, byte const *strptr, dword lswlen, dword mswlen);
/*
 *  puts bytes from strptr into X and pad out; appends length 
 *  and finally, compresses the last block(s)
 *  note: length in bits == 8 * (lswlen + 2^32 mswlen).
 *  note: there are (lswlen mod 64) bytes left in strptr.
 */

#if defined(__cplusplus)
}
#endif

#endif  /* SILKWORM_CRYPTO_RMD160_H_ */

/*********************** end of file rmd160.h ***********************/

