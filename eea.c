// #include <stdio.h>
// #include "platform.h"
// #include "xil_cache.h"
// #include "xil_printf.h"
#pragma
#include<stdlib.h>

// #include "xgpio.h"
// #include "xparameters.h"
// #include "xtime_l.h"

int add(int combo1,int combo2){
    return combo1^combo2;
}
//the concept is that multiplication is a serious of additions
int mult(int val1, int val2, int fx){
    int res=0;
    for(int i=0; i<8;i++){
        // printf("res1: %d\t", res);
        res<<=1;
        //keep shifting left until we've reached a unique value to add against the
        if(val2 & 128){
            res=res^val1;
        }
        val2<<=1;
        if(res & 256){
            //if we've reached the left most bit get rid of it.
            res=res^fx;
        }



        // printf("res2: %d\n", res);

    }
    return res;

}
int inverseTest(int valueToInvert){
    for(int i=0;i<283;i++){
        int o=mult(i,valueToInvert,283);
        if(o==1){
            return i;
        }
    }
	perror("No inverse found");
     exit(0);
    return -99;

}
int division(int r0, int r1, int* r){
    if(r0>r1){
	*r=1;
	return 0;
    }
    int a = r0>r1 ? r0 : r1;
    int b = r0<r1 ? r1 : r1;

    int temp =b;
    int temp2 = 1;
    int res =0;
    int remainder =0;
    while(a>=b){
        while(!((a^b)<=(a&b))){
            temp2 <<=1;
            b<<=1;
        }

        res=res ^temp2;
        temp2 =1;

        remainder = add(a,b);
        a=remainder;
        b=temp;
    }
    *r=remainder;
    return res;
}
int eea(int r0,int r1,int* inverse){
    //r0 is going to be our gcd
    //s2 =x
    int r_back2=r1;
    int r_back1=r0;
    int rn[100]; //we could go back to an int but I kinda like this
    int q[100];
    int c =0;
    int r=0;
    while (1){
	
        // r2=(r1)%r0;
        q[c]=division(r_back2,r_back1,&r);
        // if(c==0){
        //     rn[c] = add(r_back2,q[c]*r_back1);
        // }
        // else{
        rn[c] = add(r_back2,mult(q[c],r_back1,283));
        if(rn[c]>=256){
            // division(rn[c],283,&r);
            rn[c]= r;
        }
        // }
        r_back2=r_back1;
        r_back1=rn[c];
        // s2=(s0)-(r1/r0)*s1;
        if (rn[c] ==1){
            break;
        }
	if(c>500){
		printf("CRITICAL FAILURE IN MAIN LOOP!\n");
		break;	
	}
        c++;
    }
    int b_2Back=0;
    int b_1Back=1;
    int i= 0; //counter
    int bn[100];
	
    while (1){

        bn[i] = add(b_2Back,mult(q[i],b_1Back,283));
        b_2Back=b_1Back;//255
        b_1Back=bn[i];//25eea
        if (i ==c){
            *inverse= bn[i];

            return b_2Back;
        }
	fflush(stdout);
        i++;
	if(i>100){
		printf("Critical FAILURE!");
		break;
		}
        }
}
