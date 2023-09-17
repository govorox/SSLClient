# Code Standards

## Tests
- Should follow the AAA princple.   

## Layout
- Indentation=2 spaces.
- Generally all IF blocks, SWITCH statements and LOOPS to have a line break above and below to add visibility to flow control.  
- IF statements to be written correctly with curly braces although inline IF statements are permitted.  
  
## Logging
- Log levels inside a library `verbose`, `debug`, `warning`, `error`  

## Firmware Development
- Simple control flow: no goto, setjump, longjump or recursion.  
  
- Limit all loops: set an upper limit for maximum number of iterations, set as an integer.  
  
- Do not use the Heap at all: heap and garbage collectors cannot be proven by a static code analyser. By not using heap and instead using the stack memory leaks are eliminated.  
    
- Limit function size: limit to max 60 lines and apply Single responsibility principle.  
  
- Practice Data hiding: declare variables at teh lowest scope required: reduces access, aids analysis and debugging.  
  
- Check all return values for non void functions: or cast to (void) otherwise a code review will throw it back as not correctly implemented.  
  
- Limit C preprocessor to simple declarations: why? "The C preprocessor is a poweful obfuscatino tool that can destroy code clarity and beffudle text based code checkers".  
	- expecially when conditional create more compilation targets - which then require testing. This makes code harder to scale.  
  
- Restrict pointer use: never dereference more than one layer at a time. Limit use of function pointer at all as this makes the flow control graph for programs less clear and much harder to statically analyse.  
  
- Be Pedantic!: gcc -Wall -Werror -Wpedantic  
  
- Test Test Test: using different analysers with different rule sets.