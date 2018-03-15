package edu.uestc.jerryxie.security.secureknn;

import org.apache.commons.math3.linear.RealMatrix;
import org.apache.commons.math3.linear.LUDecomposition;
import org.apache.commons.math3.linear.Array2DRowRealMatrix;

import java.util.Random;


public class secureKnn {
    private int dp,d;
    private double dM1[][],dM2[][];
    private RealMatrix M1,M2;
    private int s[],w[];
    private double pa[][],pb[][];
    private double qa[],qb[];   //查询向量
    private int nowtuple;  //当前可用的tuple下标
    private RealMatrix M1R,M2R; //M1 M2的逆矩阵
    private RealMatrix M1TR,M2TR; //M1T M2T的逆矩阵
    private int a[];  //快速排序用数组
    public int ret[];
    public secureKnn(int dpe,int de,int n) //初始化类参数 dpe：d' de：d  n：数据库中有多少个向量
    {
        int i,j;
        int maxd=50; //生成50以内的随机数
        int flag0,flag1;
        this.dp=dpe;
        this.d=de;
        dM1=new double[dp][dp];
        dM2=new double[dp][dp];
        s=new int[dp];
        w=new int[dp];
        pa=new double[n][dp];
        pb=new double[n][dp];
        nowtuple=0;
        Random r=new Random();
        while(true)  //随机生成可逆矩阵M1，作为密钥
        {
            for(i=0;i<dp;i++)
                for(j=0;j<dp;j++)
                    dM1[i][j]=r.nextInt(maxd+1);
            M1=new Array2DRowRealMatrix(dM1);
            LUDecomposition lM1=new LUDecomposition(M1);
            if(lM1.getDeterminant()!=0.0)
                break;
        }
        while(true)  //随机生成可逆矩阵M2，作为密钥
        {
            for(i=0;i<dp;i++)
                for(j=0;j<dp;j++)
                    dM2[i][j]=r.nextInt(maxd+1);
            M2=new Array2DRowRealMatrix(dM2);
            LUDecomposition lM2=new LUDecomposition(M2);
            if(lM2.getDeterminant()!=0.0)
                break;
        }
        flag0=0;
        flag1=0;
        while(true)
        {
            for(i=0;i<dp;i++)
            {
                s[i]=r.nextInt()%2;
                if(s[i]<0)
                {
                    i--;
                    continue;
                }
                if(s[i]==0)
                    flag0=1;
                else
                    flag1=1;
            }
            if(flag0==1 && flag1==1)
                break;
        }
        for(i=d+1;i<dp;i++)
            w[i]=r.nextInt()%500;
        //生成M1和M2的逆矩阵
        M1R=new LUDecomposition(M1).getSolver().getInverse();
        M2R=new LUDecomposition(M2).getSolver().getInverse();
        //生成M1T和M2T的逆矩阵，用于解密
        M1TR=new LUDecomposition(M1.transpose()).getSolver().getInverse();
        M2TR=new LUDecomposition(M2.transpose()).getSolver().getInverse();
        return;
    }
    public void addTuple(double p[])  //把明文向量进行加密，并存储
    {
        double[] pj=new double[dp];
        int i,q;
        double t=1.0;
        RealMatrix pam,pbm;  //分割后的pa和pb
        RealMatrix pap,pbp; //加密后的pa和pb
        Random r=new Random();
        for(i=0;i<d;i++)
            pj[i]=p[i];
        for(i=0;i<d;i++)
            t+=(p[i]*p[i]);
        pj[d]=(-0.5)*t;
        for(i=d+1;i<dp;i++)
            if(s[i]==1)
                pj[i]=w[i];
            else if(s[i]==0)
                pj[i]=r.nextInt()%500;
            else;
        q=dp-1;
        while(true)  //寻找最后一个s[i]=0的维度
        {
            if(s[q]==1)
                q--;
            if(s[q]==0)
                break;
        }
        //使得人工维度的点积为0，不影响原有计算
        t=0.0;
        for(i=d+1;i<q;i++)
        {
            if(s[i]==1)
                continue;
            t+=(w[i]*pj[i]);
        }
        t/=w[q];
        t=(-1)*t;
        pj[q]=t;
        //执行分割操作
        for(i=0;i<dp;i++)
        {
            if(s[i]==1)
            {
                pa[nowtuple][i]=pj[i]/2;
                pb[nowtuple][i]=pj[i]/2;
            }
            if(s[i]==0)
                pa[nowtuple][i]=pb[nowtuple][i]=pj[i];
        }
        //执行加密操作
        pam=new Array2DRowRealMatrix(pa[nowtuple]);
        pbm=new Array2DRowRealMatrix(pb[nowtuple]);
        pap=M1.transpose().multiply(pam);
        pbp=M2.transpose().multiply(pbm);
        double pad[][]=pap.getData();
        double pbd[][]=pbp.getData();
        for(i=0;i<dp;i++)
        {
            pa[nowtuple][i]=pad[i][0];
            pb[nowtuple][i]=pbd[i][0];
        }
        nowtuple++;
        return;
    }
    public void addQuery(double qd[])  //加密并存储q
    {
        Random ran=new Random();  //初始化随机数生成器
        double r=ran.nextInt();
        double t;
        while(r<=0) //确保r>0
            r=ran.nextInt();
        double q[]=new double[dp];
        int i,j;
        qa=new double[dp];
        qb=new double[dp];
        //计算rq
        for(i=0;i<d;i++)
            q[i]=r*qd[i];
        q[d]=r; //令d+1维为r
        for(i=d+1;i<dp;i++)  //生成扩展维度
        {
            if(s[i]==0)
                q[i]=w[i];
            else
                q[i]=ran.nextInt();
        }
        i=dp-1;
        while(true)  //寻找最后一个s[i]=1的维度
        {
            if(s[i]==0)
                i--;
            if(s[i]==1)
                break;
        }
        //使扩展出的维度在计算点积时和为0
        t=0.0;
        for(j=d+1;j<i;j++)
        {
            if(s[j]==0)
                continue;
            t+=(w[i]*q[i]);
        }
        t/=w[i];
        t=(-1)*t;
        q[i]=t;
        qa=new double[dp];
        qb=new double[dp];
        //执行分割
        for(i=0;i<dp;i++)
        {
            if(s[i]==0)
            {
                qa[i]=q[i]/2;
                qa[i]=q[i]/2;
            }
            if(s[i]==1)
            {
                qa[i]=q[i];
                qb[i]=q[i];
            }
        }
        //执行加密步骤
        RealMatrix qam=new Array2DRowRealMatrix(qa);
        RealMatrix qbm=new Array2DRowRealMatrix(qb);
        RealMatrix qap=M1R.multiply(qam);
        RealMatrix qbp=M2R.multiply(qbm);
        double[][] qab=qap.getData();
        double[][] qbb=qbp.getData();
        for(i=0;i<dp;i++)
        {
            qa[i]=qab[i][0];
            qb[i]=qbb[i][0];
        }
    }
    private boolean isnear(int a,int b)  //判断哪一个向量更接近查询向量 true: a<=b  false: a>b
    {
        double t,t1,t2;
        int i;
        t1=t2=0.0;
        if(a==b)
            return true;
        for(i=0;i<dp;i++)
        {
            t1+=(pa[a][i]-pa[b][i])*qa[i];
            t2+=(pb[a][i]-pb[a][i])*qb[i];
        }
        t=t1+t2;
        if(t>=0)
            return true;
        else
            return false;
    }

    //快速排序算法：划分部分
    public int partition(int left,int right)
    {
        int key=a[left];
        while(left<right)
        {
            while(isnear(key,a[right])&&right>left)  //从后半部分向前扫描
                right--;
            a[left]=a[right];
            while(isnear(a[left],key)&&right>left)//从前半部分向后扫描
                left++;
            a[right]=a[left];
        }
        a[right]=key;
        return right;
    }

    //快速排序算法：递归部分
    public void qsort(int left ,int right)
    {
        if(left>=right){
            return ;
        }
        int index=partition(left,right);
        qsort(left,index-1);
        qsort(index+1,right);
    }

    //搜索函数
    public void search(int k)
    {
        a=new int[nowtuple];
        ret=new int[k];
        int i;
        for(i=0;i<nowtuple;i++)
            a[i]=i;
        System.out.println(nowtuple);
        if(k>nowtuple)
            return;
        qsort(0,nowtuple-1);  //调用快速排序算法
        for(i=0;i<k;i++)    //取前k个值
            ret[i]=a[i];
    }

    public double[] decrypt(int num) //解密函数
    {
        RealMatrix pam,pbm;
        double[][] pap,pbp;
        double[] orip=new double[d];
        int i;
        //把pa和pb由数组转成矩阵
        pam=new Array2DRowRealMatrix(pa[num]);
        pbm=new Array2DRowRealMatrix(pb[num]);
        //与转置密钥矩阵的逆矩阵相乘计算原文
        pam=M1TR.multiply(pam);
        pbm=M2TR.multiply(pbm);
        pap=pam.getData();
        pbp=pbm.getData();
        //将分开的向量还原
        for(i=0;i<d;i++)
        {
            if(s[i]==0)
                orip[i]=pap[i][0];
            if(s[i]==1)
                orip[i]=pap[i][0]+pbp[i][0];
        }
        return orip;
    }
}
