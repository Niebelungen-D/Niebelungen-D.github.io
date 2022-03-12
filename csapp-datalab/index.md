# CSAPP Datalab


# CSAPP-Datalab

labs系列的第一个lab，主要考查书中第二章的知识。挺烧脑的。。。

<!-- more -->

## List

|        Name         |         Description          | Rating | Max ops |
| :-----------------: | :--------------------------: | :----: | :-----: |
|    bitCor (x, y)    | `x^y` using only `~` and `&` |   1    |   14    |
|       tmin()        |         返回最小补码         |   1    |    4    |
|      isTmax(x)      |     判断是否为补码最大值     |   1    |   10    |
|    allOddBits(x)    | 判断补码所有奇数位是否都是1  |   2    |   12    |
|      negate(x)      |      不使用`-`实现`-x`       |   3    |    5    |
|   isAsciDigit(x)    |    判断`x`是否是`ASCII`码    |   3    |   15    |
|     conditional     |       实现`x ? y : z`        |   3    |   16    |
| isLessOrEqual(x, y) |            `x<=y`            |   3    |   24    |
|   logicalNeg(x))    |      计算`!x`而不用`!`       |   3    |   12    |
|   howManyBits(x)    |  计算表达`x`所需的最少位数   |   4    |   90    |
|   float_twice(uf)   |         计算`2.0*uf`         |   4    |   30    |
|    float_i2f(uf)    |       计算`(float) f`        |   4    |   30    |
|    float_f2i(uf)    |        计算`(int) f`         |   4    |   30    |

## bitCor (x, y)

```c
/* 
 * bitXor - x^y using only ~ and & 
 *   Example: bitXor(4, 5) = 1
 *   Legal ops: ~ &
 *   Max ops: 14
 *   Rating: 1
 */
int bitXor(int x, int y) {
  return ~(~x&~y)&~(x&y);
}
```

就像数电中的异或拆开一样。

## tmin()

```c
/* 
 * tmin - return minimum two's complement integer 
 *   Legal ops: ! ~ & ^ | + << >>
 *   Max ops: 4
 *   Rating: 1
 */
int tmin(void) {
  return 1<<31;
}
```

最小的补码，正数位全为零，符号位为1。

## isTmax(x)

```c
/*
 * isTmax - returns 1 if x is the maximum, two's complement number,
 *     and 0 otherwise 
 *   Legal ops: ! ~ & ^ | +
 *   Max ops: 10
 *   Rating: 2
 */
int isTmax(int x) {
  int i=x+1;
  x+=i;
  x=~x;//get a zero only if x=0xfff..ff or 0x7ff..ff
  i=!i;
  x=x+i;
  return !x;
}
```

`7ffff...`的一个特性，其+1后的结果与原数的和为`ffffff...`，而`ffff...`也有这个特性，所以通过这个性质可以过滤其他数，取反之后为`0000000...`。第二个性质，`7ffff...`+1之后不为0，而`ffffff...`+1后为0。通过这个性质来过滤`ffffff...`

## allOddBits(x)

```c
/* 
 * allOddBits - return 1 if all odd-numbered bits in word set to 1
 *   Examples allOddBits(0xFFFFFFFD) = 0, allOddBits(0xAAAAAAAA) = 1
 *   Legal ops: ! ~ & ^ | + << >>
 *   Max ops: 12
 *   Rating: 2
 */
int allOddBits(int x) {
  int m=0xAA+(0xAA<<8);
  m=m+(m<<16);
  return !((m&x)^m));
}
```

构造出奇数位全为1的数`0xAAAAAAAA`，与`x`相与取得其奇数位，再进行异或取反，相同为1，不同为0。

## negate(x)

```c
/* 
 * negate - return -x 
 *   Example: negate(1) = -1.
 *   Legal ops: ! ~ & ^ | + << >>
 *   Max ops: 5
 *   Rating: 2
 */
int negate(int x) {
  x=~x+1;
  return x;
}
```

 ## isAsciiDigit(x)

```c
/* 
 * isAsciiDigit - return 1 if 0x30 <= x <= 0x39 (ASCII codes for characters '0' to '9')
 *   Example: isAsciiDigit(0x35) = 1.
 *            isAsciiDigit(0x3a) = 0.
 *            isAsciiDigit(0x05) = 0.
 *   Legal ops: ! ~ & ^ | + << >>
 *   Max ops: 15
 *   Rating: 3
 */
int isAsciiDigit(int x) {
  int A=x+(~0x39+1);//x-0x39<=0-->x+~0x39+1<=0-->(x+~0x39+1)>>31
  int B=!((x+(~0x30+1))>>31);//x-0x30>=0-->x+~0x30+1>=0-->!((x+~0x30+1)>>31)
  return B&((!A)|(A>>31));
}
```

## conditional(x , y, z)

```c
/* 
 * conditional - same as x ? y : z 
 *   Example: conditional(2,4,5) = 4
 *   Legal ops: ! ~ & ^ | + << >>
 *   Max ops: 16
 *   Rating: 3
 */
int conditional(int x, int y, int z) {
  x=!!x;
  x=~x+1;
  return (x&y)|((~x)&z);
}
```

先将x转化为逻辑值。x为真时让x与y的运算等于y，x与z的运算为0.因为要保存数值，所以想到&操作。因为我们要保存所有位，所以取其相反数。取z的情况正好相反。

## isLessOrEqual(x, y)

```c
/* 
 * isLessOrEqual - if x <= y  then return 1, else return 0 
 *   Example: isLessOrEqual(4,5) = 1.
 *   Legal ops: ! ~ & ^ | + << >>
 *   Max ops: 24
 *   Rating: 3
 */
int isLessOrEqual(int x, int y) {
  int A=(x>>31)&1;
  int B=(y>>31)&1;
  int C=A^B;
  int D=((y+(~x+1))>>31)&1;  
  return (C&A)|(!C&!D);
}
```

不同符号的数相减会出现溢出，所以分为两种情况

- 符号不同，x符号为1时，条件为真。
- 符号相同，进行y-x，当且仅当符号位为0时，条件为真。

## logicalNeg(x))

```c
/* 
 * logicalNeg - implement the ! operator, using all of 
 *              the legal operators except !
 *   Examples: logicalNeg(3) = 0, logicalNeg(0) = 1
 *   Legal ops: ~ & ^ | + << >>
 *   Max ops: 12
 *   Rating: 4 
 */
int logicalNeg(int x) {
  return (~(x|(~x+1))>>31)&1;
}
```

0的相反数是其本身~

## howManyBits(x)

```c
/* howManyBits - return the minimum number of bits required to represent x in
 *             two's complement
 *  Examples: howManyBits(12) = 5
 *            howManyBits(298) = 10
 *            howManyBits(-5) = 4
 *            howManyBits(0)  = 1
 *            howManyBits(-1) = 1
 *            howManyBits(0x80000000) = 32
 *  Legal ops: ! ~ & ^ | + << >>
 *  Max ops: 90
 *  Rating: 4
 */
int howManyBits(int x) {
    int b16,b8,b4,b2,b1,b0;
  int sign=x>>31;
  x = (sign&~x)|(~sign&x);
  b16 = !!(x>>16)<<4;
  x = x>>b16;
  b8 = !!(x>>8)<<3;
  x = x>>b8;
  b4 = !!(x>>4)<<2;
  x = x>>b4;
  b2 = !!(x>>2)<<1;
  x = x>>b2;
  b1 = !!(x>>1);
  x = x>>b1;
  b0 = x;
  return b16+b8+b4+b2+b1+b0+1;
}
```

如果是一个正数，则需要找到它最高的一位（假设是n）是1的，再加上符号位，结果为n+1；如果是一个负数，则需要知道其最高的一位是0的（例如4位的1101和三位的101补码表示的是一个值：-3，最少需要3位来表示）。

## float_twice(uf)

```c
/* 
 * float_twice - Return bit-level equivalent of expression 2*f for
 *   floating point argument f.
 *   Both the argument and result are passed as unsigned int's, but
 *   they are to be interpreted as the bit-level representation of
 *   single-precision floating point values.
 *   When argument is NaN, return argument
 *   Legal ops: Any integer/unsigned operations incl. ||, &&. also if, while
 *   Max ops: 30
 *   Rating: 4
 */
unsigned float_twice(unsigned uf) {
  int exp=(uf&0x7f800000)>>23;
  int sign=uf&(1<<31);
  if(exp==0) return (uf<<1)|sign;
  if(exp==255) return uf;
  exp++;
  if(exp==255) return 0x7f800000|sign;
  return (exp<<23|sign)|(uf&0x807fffff);
}
```

`*2`只需要对其exp字段进行操作，并根据浮点数的不同情况返回数值。

## float_i2f(uf)

```c
/* 
 * float_i2f - Return bit-level equivalent of expression (float) x
 *   Result is returned as unsigned int, but
 *   it is to be interpreted as the bit-level representation of a
 *   single-precision floating point values.
 *   Legal ops: Any integer/unsigned operations incl. ||, &&. also if, while
 *   Max ops: 30
 *   Rating: 4
 */
unsigned float_i2f(int x) {
  unsigned ux, mask, temp, e, sign = 0;
	int E = 0, count;	
	if(!x) return 0; 
	if(x&0x80000000){
		ux = ~x+1;
		sign = 0x80000000;
	}
	else ux=x;
	temp = ux;
	while(temp){
		E += 1;
		temp = temp>>1;
	}
	ux = ux&(~(1<<(E-1))); 
	e = E+126; 
	if(E<=24){
		ux = ux<<(24-E);
	}else{
		count = 0;
		while(E>25){
			if(ux&0x01) count+=1;
			ux = ux>>1;
			E -= 1;
		}
		mask = ux&0x01;
		ux = ux>>1;
		if(mask){
			if(count) ux+=1;
			else{
				if(ux&0x01) ux+=1;
			}
		}
		if(ux>>23){
			e+=1;
			ux = ux&0x7FFFFF;
		}
	}	
  return sign+(e<<23)+ux;
}
```

将补码转化为浮点数编码步骤：

1. 将补码转化为无符号数，并根据补码的符号来设置浮点数的符号位

2. 因为补码一定是大于等于0的数，所以要么为0，要么为规格化数。如果是规格化数，首先统计除了最高有效位外一共需要几位，得到的就是E，然后通过$ E = e + 1-2^{k-1}$得到解码位为 $e=E-1+2^{k-1}$。

3. 无符号数后面E位就是尾数部分，但是需要判断该部分是否23位，如果小于23位，直接将其左移填充；如果大于23位，需要对其进行舍入：

4. 1. 如果是中间值，就需要向偶数舍入
   2. 如果不是中间值，就需要向最近的进行舍入

## float_f2i(uf)

```c
/* 
 * float_f2i - Return bit-level equivalent of expression (int) f
 *   for floating point argument f.
 *   Argument is passed as unsigned int, but
 *   it is to be interpreted as the bit-level representation of a
 *   single-precision floating point value.
 *   Anything out of range (including NaN and infinity) should return
 *   0x80000000u.
 *   Legal ops: Any integer/unsigned operations incl. ||, &&. also if, while
 *   Max ops: 30
 *   Rating: 4
 */
int float_f2i(unsigned uf) {
  int s_    = uf>>31;
  int exp_  = ((uf&0x7f800000)>>23)-127;
  int frac_ = (uf&0x007fffff)|0x00800000;
  if(!(uf&0x7fffffff)) return 0;

  if(exp_ > 31) return 0x80000000;
  if(exp_ < 0) return 0;

  if(exp_ > 23) frac_ <<= (exp_-23);
  else frac_ >>= (23-exp_);

  if(!((frac_>>31)^s_)) return frac_;
  else if(frac_>>31) return 0x80000000;
  else return ~frac_+1;
}
```

将浮点数转化为补码步骤：

1. 首先假设浮点数为规格化数，则 $E=e-bias$得到指数部分，我们知道如果$E<0$，则计算出来的结果一定是小数（包括非规格化数），此时能直接舍入到0；如果 $E>31$，表示至少要将尾数部分右移31位，此时一定会超过补码的表示范围，所以直接将其溢出。
2. 可通过最低23位得到尾数部分
3. 尾数部分需要自己在最高有效位添1，如果是负数，则补码的最高位为1，就要求其对应的无符号编码最高位不为1，否则是负溢出溢出；如果是整数，则补码的最高位为0，就要求其编码的最高位为0，否则是正溢出。

必须纪念一下~~

```bash
niebelungen@LAPTOP-xxxxxxxx:/mnt/c/download/datalab-handout$ ./btest
Score   Rating  Errors  Function
 1      1       0       bitXor
 1      1       0       tmin
 2      2       0       isTmax
 2      2       0       allOddBits
 2      2       0       negate
 3      3       0       isAsciiDigit
 3      3       0       conditional
 3      3       0       isLessOrEqual
 4      4       0       logicalNeg
 4      4       0       howManyBits
 4      4       0       float_twice
 4      4       0       float_i2f
 4      4       0       float_f2i
Total points: 37/37
```

