# CSAPP Lecture 05




# Lecture 05: Program Optimization

**程序的性能**：引入每元素周期数（Cycles Per Element， CPE）作为衡量标准。因为处理器的活动顺序是由时钟控制的，时间长短代表执行的指令数目。

<!-- more -->

## 通用的有效优化

**代码移动(Code Motion)**：先计算需要计算的值，然后在之后一直使用这个值

```c
void set_row(double *a, double *b, long i, long n)
{
    long j;
    for(j = 0; j < n; j++)
        a[n*i+j]=b[j];
}
```

在这个例子中每次循环都会计算n*i，即多了很多不必要的乘法运算。看下面的优化

```c
void set_row(double *a, double *b, long i, long n)
{
    long j;
    int ni=n*i
    for(j = 0; j < n; j++)
        a[ni+j]=b[j];
}
```

**计算量减少**：将乘法转化为加法

**共享通用表达**：通过抽取子表达式，将其提前转化为共享变量的方式减少计算量

```c
int v1 = a[n*i+j*0];
int v2 = a[n*i+j*1];
int v3 = a[n*i+j*2];
```

优化

```c
int ni=n*i
int v1 = a[ni+j*0];
int v2 = a[ni+j*1];
int v3 = a[ni+j*2];
```

## Loop Unrolling 循环展开

```c
void psum1(float a[], float p[], long n){
  long i;
  p[0] = a[0];
  for(i=1, i<n; i++){
    p[i] = p[i-1]+a[i];
  }
} 

void psum2(float a[], float p[], long n){
  long i;
  p[0] = a[0];
  for(i=1; i<n-1; i+=2){
    float mid_val = p[i-1]+a[i];
    p[i] = mid_val;
    p[i+1] = mid_val+a[i+1];
  }
  if(i<n){
    p[i] = p[i-1]+a[i];
  }
}
```

**kx1循环展开**

将一个循环展开成了两部分，第一部分是每次循环处理k个元素，能够减少循环次数；第二部分处理剩下还没计算的元素，是逐个进行计算的。

```c
#define k 2
void combine5(vec_ptr v, data_t *dest){
  long i;
  long length = vec_length(v);
  long limit = length-k+1;
  data_t *data = get_vec_start(v);
  data_t acc = IDENT;
  for(i=0; i<limit; i+=k){
    acc = ((acc OP data[i]) OP data[i+1]) ... OP data[i+k-1];
  }
  for(; i<length; i++){
    acc = acc OP data[i];
  }
  return acc;
}
```

**kxk循环展开**

将一个循环展开成了两部分，第一部分是每次循环处理k个元素，能够减少循环次数，并且引入k个变量保存结果；第二部分处理剩下还没计算的元素，是逐个进行计算的。

```c
#define K 2
void combine6(vec_ptr v, data_t *dest){
  long i;
  long length = vec_length(v);
  long limit = length-k+1;
  data_t *data = get_vec_start(v);
  data_t acc0 = IDENT;
  data_t acc1 = IDENT;
  ...
  data_t acck_1 = IDENT; //k个变量

  for(i=0; i<limit; i+=k){
    acc0 = acc0 OP data[0];
    acc1 = acc1 OP data[1];
    ...
    acck_1 = acck_1 OP data[k-1]; //更新k个变量
  }  
  for(; i<length; i++){
    acc0 = acc0 OP data[i];
  }
  *dest = acc0 OP acc1 OP ... OP acck_1;
}
```

