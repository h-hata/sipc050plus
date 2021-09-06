#include	<math.h>
#include	<stdio.h>
#include	<malloc.h>
#include	"fft.h"


static	double	*Sin=NULL;
static	double	*Cos=NULL;
static	int	n_s=0;


int fft(int d,int llen,double *x,double *y)
//d:1 FFT d:-1 逆FFT
//llen データ数の指数部　llen=7->128 8->256 9->512 10->1024
//x:実部
//y:虚部(FFTの場合は要素はオール０）
{

	int i,j,k,n,n1,n2,n3,m1,m2;
	double r,sign,w1,w2,t1,t2;
	double *ts,*tc;

	//d:1 FFT d:-1 逆FFT
	sign=(d<0)?1.0:-1.0;
	for(n=i=1;i<llen;i++)
		n<<=1;
	if(n_s!=0 && n_s!=n){
		if(Sin!=NULL) {
			free(Sin);
			Sin=NULL;
		}
		if(Cos!=NULL) {
			free(Cos);
			Cos=NULL;
		}
	}
	if(Sin==NULL){
		Sin=malloc(n*sizeof(double));
		if(Sin==NULL) return -1;
		Cos=malloc(n*sizeof(double));
		if(Cos==NULL){
			free(Sin);
			return -1;
		}
		ts=Sin;
		tc=Cos;
		r=4.0*atan(1.0)/n;  // PI/n;
		for(i=0;i<n;i++){
			ts[i]=sin(r*i);
			tc[i]=cos(r*i);
		}
	}
	ts=Sin;
	tc=Cos;
	n*=2;
	n2=n;
	for(i=0;i<llen;i++){
		n1=n2;
		n2>>=1;
		n3=n/n1;
		for(j=0;j<n2;j++){
			w1= tc[j*n3];
			w2= sign*ts[j*n3];
			for(k=n1;k<=n;k+=n1){
				m1=j+k-n1;
				m2=m1+n2;
				t1=x[m1]-x[m2];
				t2=y[m1]-y[m2];
				x[m1]+=x[m2];
				y[m1]+=y[m2];
				x[m2]=w1*t1-w2*t2;
				y[m2]=w1*t2+w2*t1;
			}
		}
	}
	n1=n-1;
	n2=n>>1;
	for(i=j=0;i<n1;i++){
		k=n2;
		//回転
		if(i<j){
			t1=x[i];
			t2=y[i];
			x[i]=x[j];
			y[i]=y[j];
			x[j]=t1;
			y[j]=t2;
		}
		while(k<=j){
			j-=k;
			k>>=1;
		}
		j+=k;
	}
	if(d==1){
		sign=1.0/n;
		for(i=0;i<n;i++){
			*x++*=sign;
			*y++*=sign;
		}
	}
	return 0;
}

