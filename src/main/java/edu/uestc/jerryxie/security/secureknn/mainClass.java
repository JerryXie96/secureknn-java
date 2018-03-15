package edu.uestc.jerryxie.security.secureknn;

import edu.uestc.jerryxie.security.secureknn.secureKnn;

import java.util.Scanner;

public class mainClass {
    public static void main(String argv[])
    {
        Scanner s=new Scanner(System.in);
        int d,dpe,n,i,j,k;
        double seavec[];
        double vec[];
        int order[];
        System.out.println("Please input the d (the number of dimensions of vectors) d' (the number of dimensions of external vectors) and n (the number of vectors):");
        d=s.nextInt();
        dpe=s.nextInt();
        n=s.nextInt();
        secureKnn sk=new secureKnn(dpe,d,n);
        vec=new double[d];
        seavec=new double[d];
        System.out.println("Initialization Completed.");
        System.out.println("Vectors Addition Section Begins.");
        for(i=0;i<n;i++)
        {
            for(j=0;j<d;j++)
                vec[j]=s.nextDouble();
            sk.addTuple(vec);
        }
        System.out.println("Vectors Addition Section Completed.");
        System.out.println("Searching Vector Addition Section Begins.");
        System.out.println("Input your searching vector.");
        for(i=0;i<d;i++)
            seavec[i]=s.nextDouble();
        sk.addQuery(seavec);
        System.out.println("Searching Vector Addition Section Completed.");
        System.out.println("Searching Section Begins.");
        while(true)
        {
            System.out.println("Input k (k of kNN). Input -1 to end this section.");
            k=s.nextInt();
            if(k>n)
            {
                System.out.println("Parameter Error.");
                continue;
            }
            if(k==-1)
                break;
            sk.search(k);
            System.out.println("The order numbers are:");
            for(i=0;i<k;i++)
                System.out.print(sk.ret[i]+" ");
            System.out.println();
        }
        System.out.println("Searching Section Completed.");
        System.out.println("Decryption Section Begins.");
        while(true)
        {
            System.out.println("Input the order number of the vector you want to decrypt (0 to start). Input -1 to end this section.");
            k=s.nextInt();
            if(k>=n)
            {
                System.out.println("Parameter Error.");
                continue;
            }
            if(k==-1)
                break;
            vec=sk.decrypt(k);
            System.out.println("The decrypted vector is:");
            for(i=0;i<d;i++)
                System.out.print(vec[i]+" ");
            System.out.println();
        }
        System.out.println("Decryption Section Completed.");
        System.out.println("Programme Finished.");
        return;
    }
}
