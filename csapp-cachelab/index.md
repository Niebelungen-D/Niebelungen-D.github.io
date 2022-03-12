# CSAPP Cachelab


# CSAPP-Cachelab

<!--more-->

## part A

模拟cache

```c
#include "cachelab.h"
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>

#define BUFFER_SIZE 50
char buf[BUFFER_SIZE];

int s;	  
int E;	  
int b;	  
char *t;	

int cache_size;
long long *cache;       

unsigned time_stamp;
unsigned *last_used_time;

int hit_count;
int miss_count;
int eviction_count;

void memoryAccess(long long addr) {
	++time_stamp;

	int set_idx = (addr >> b) & ((1 << s) - 1);
	long long tag = addr >> (b + s);

	long long *set_cache = cache + set_idx * E;
	unsigned *set_used_time = last_used_time + set_idx * E;

	int i;
	unsigned LRU_i = -1;
	unsigned LRU_valid;
	unsigned LRU_time;
	for (i = 0; i < E; ++i) {
		unsigned valid = set_cache[i] & 1;
		long long tag_i = set_cache[i] >> 1;
		if (valid > 0 && tag == tag_i) {
			++hit_count;
			set_used_time[i] = time_stamp;
			return ;
		} else {
			if (LRU_i == -1
			  || valid < LRU_valid
			  || (valid == LRU_valid&&
			      set_used_time[i] < LRU_time)) {
				LRU_i = i;
				LRU_valid = valid;
				LRU_time = set_used_time[i];
			}
		}
	}

	++miss_count;
	eviction_count += LRU_valid;
	set_used_time[LRU_i] = time_stamp;
	set_cache[LRU_i] = tag << 1 | 1;
}

int main(int argc, char *argv[]) {
	char *optString = "s:E:b:t:";
	int opt = getopt(argc, argv, optString);
	while (~opt) {
		switch (opt) {
			case 's': s = atoi(optarg); break;
			case 'E': E = atoi(optarg); break;
			case 'b': b = atoi(optarg); break;
			case 't': t = optarg; break;
		}
		opt = getopt(argc, argv, optString);
	}

	time_stamp = 0;
	hit_count = miss_count = eviction_count = 0;
	cache_size = E << s;
	cache = (long long *) malloc(sizeof(*cache) * cache_size);
	last_used_time = (unsigned *) malloc(sizeof(*last_used_time) * cache_size);
	memset(cache, 0, sizeof(*cache) * cache_size);

	FILE *fp = fopen(t, "r");
	while (fgets(buf, BUFFER_SIZE, fp) != NULL) {
		int len = strlen(buf);
		if (len <= 2 || buf[0] != ' ') continue;
		char op = buf[1];
		if (!(op == 'L' || op == 'S' || op == 'M'))
			continue;
		int i;
		for (i = 0; i < len; ++i)
			if (buf[i] == ',') {	   
				buf[i] = '\0';
				break;
			}
		buf[1] = '0', buf[2] = 'x';
		long long addr;
		sscanf(buf + 1, "%llx", &addr);
		printf("op = %c, addr = %llx, ", op, addr);
		memoryAccess(addr);
		if (op == 'M') ++hit_count;
	}
	printSummary(hit_count, miss_count, eviction_count);

	fclose(fp);
	return 0;
}
```

## part B

要求实现数组转置，并且有限制：

- 缓存参数为：s = 5, E = 1, b = 5。
- 最多能够定义 12 个 int 类型的局部变量。
- 不允许修改矩阵 A，但能任意修改矩阵 B。

由就硬分块，分八块，加上一些变量能最大利用局部变量。32*32的矩阵分八块，将八块全部读入再写。64\*64矩阵先分八块，再四块。61\*67分16块。

64*64用了分块矩阵转置的知识
$$
 \begin{Bmatrix}
   A_{11} & A_{12}  \\
   A_{21} & A_{22} 
  \end{Bmatrix}  =  \begin{Bmatrix}
   A^T_{11} & A^T_{21}  \\
   A^T_{12} & A^T_{22} 
  \end{Bmatrix}
  
$$
将其分为32*32的四块，子矩阵分八块转置，再分四块交换对角线子矩阵。

```c
void transpose_submit(int M, int N, int A[N][M], int B[M][N]) {
    int i, j, k, h;
    int a1, a2, a3, a4, a5, a6, a7, a8;
    if(N==32) {
        for (i = 0; i < N; i+=8) {
            for (j = 0; j < M; j+=8) {
                for(k=i; k<i+8; ++k) {
                    a1 = A[k][j];
                    a2 = A[k][j+1];
                    a3 = A[k][j+2];
                    a4 = A[k][j+3];
                    a5 = A[k][j+4];
                    a6 = A[k][j+5];
                    a7 = A[k][j+6];
                    a8 = A[k][j+7];

                    B[j][k] = a1;
                    B[j+1][k] = a2;
                    B[j+2][k] = a3;
                    B[j+3][k] = a4;
                    B[j+4][k] = a5;
                    B[j+5][k] = a6;
                    B[j+6][k] = a7;
                    B[j+7][k] = a8;
                }
            }
        }
    } else if(N==64) {
        for(i=0; i<N; i+=8) {
            for(j=0; j<M; j+=8) {
                for(k=j; k<j+4; ++k) {
                    a1=A[k][i];
                    a2=A[k][i+1];
                    a3=A[k][i+2];
                    a4=A[k][i+3];
                    a5=A[k][i+4];
                    a6=A[k][i+5];
                    a7=A[k][i+6];
                    a8=A[k][i+7];

                    B[i][k]=a1;
                    B[i][k+4]=a5;
                    B[i+1][k]=a2;
                    B[i+1][k+4]=a6;
                    B[i+2][k]=a3;
                    B[i+2][k+4]=a7;
                    B[i+3][k]=a4;
                    B[i+3][k+4]=a8;
                }
                for(k=i; k<i+4; ++k) {
                    a1=B[k][j+4];
                    a2=B[k][j+5];
                    a3=B[k][j+6];
                    a4=B[k][j+7];
                    a5=A[j+4][k];
                    a6=A[j+5][k];
                    a7=A[j+6][k];
                    a8=A[j+7][k];

                    B[k][j+4]=a5;
                    B[k][j+5]=a6;
                    B[k][j+6]=a7;
                    B[k][j+7]=a8;
                    B[k+4][j]=a1;
                    B[k+4][j+1]=a2;
                    B[k+4][j+2]=a3;
                    B[k+4][j+3]=a4;
                }
                for(k=i+4; k<i+8; ++k) {
                    a1=A[j+4][k];
                    a2=A[j+5][k];
                    a3=A[j+6][k];
                    a4=A[j+7][k];

                    B[k][j+4]=a1;
                    B[k][j+5]=a2;
                    B[k][j+6]=a3;
                    B[k][j+7]=a4;
                }
            }
        }
    } else if(M==61) {
        for(i=0; i<N; i+=16) {
            for(j=0; j<M; j+=16) {
                for(k=i; k<i+16&&k<N; ++k) {
                    for(h=j; h<j+16&&h<M; ++h) {
                        B[h][k] = A[k][h];
                    }
                }
            }
        }
    }
}
```


