def formuleDeViete(roots):
      # Declare an array for  polynomial coefficient.
    n = len(roots)
    coeff = [0] * (n + 1)
      
    # Set Highest Order coefficient as 1
    coeff[n] = 1
    for i in range(1, n + 1):
        for j in range(n - i - 1, n):
            coeff[j] += ((-1) * roots[i - 1] * coeff[j + 1])  
    
    print("Polynomial Coefficients : ", end = "")
    for i in coeff: 
        print(i, end = " ")
    print()

    return coeff
