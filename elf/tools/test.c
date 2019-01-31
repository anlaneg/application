/*
 * test.c
 *
 *  Created on: Jan 31, 2019
 *      Author: anlang
 */

static int d=0;

int func(void)
{
    return 0;
}

int main(int argc, char**argv)
{
    int a;
    int b;

    a = func();
    b = func();

    return a + b + d;
}
