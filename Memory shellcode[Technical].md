# Goby Exploits Memory Shellcode Technology Details [Technical Edition]

## 01 Introduction

This is the third article in Goby's community memory shellcode series. The first article, "Ghost King in Shell - JAVAWEB Memory Shellcode [Cognitive]" introduced the history and classification of JavaWeb memory shellcode technology, and introduced common JavaWeb memory shellcode technology from a cognitive perspective; the second article, "Using Goby to Inject Memory Shellcode with Deserialization Vulnerabilities [Exploit]" mainly introduced how to combine memory shellcode with vulnerabilities to enable Goby to inject memory shellcode with one-click through deserialization vulnerabilities, and integrate with Goby's PoC and extension system. Users only need to click a few buttons to complete the injection of vulnerabilities with one-click.
This article mainly introduces some technical details used in the process of using Goby to inject memory shellcode with one-click through deserialization vulnerabilities, based on the first two articles. Of course, users do not need to know these details during the injection process using Goby PoC, but understanding and learning the technology helps to grasp some common ideas.
This article is mainly divided into three parts: "Exploiting Pre-Vulnerabilities", "Generating Memory Shellcode", and "Using Memory Shellcode", sharing some technical points and details or pitfalls related to Goby, and welcome everyone to discuss together.
Here is a brief demonstration of the use of some related technologies. The following video demonstrates the use of Goby to inject a Filter-type memory shellcode with one-click through deserialization, and carry false information through a custom URLClassLoader to avoid security personnel's investigation. The purpose is achieved by clearing the log without a trace.

[![Goby to inject a Filter-type memory shellcode with one-click through deserialization](https://i.ytimg.com/vi/k5p7IwEA0ss/maxresdefault.jpg)](https://youtu.be/k5p7IwEA0ss "Goby to inject a Filter-type memory shellcode with one-click through deserialization")

> The one-click Memory shellcode injection feature of Goby can be used for free in the community version. Click the link at the end of the article to download and experience it.



## 02 Pre-vulnerability Exploitation

First, let's talk about the pre-vulnerability exploitation. As mentioned in previous articles, from the perspective of practical vulnerability exploitation and weaponized development, we tend to inject a memory shellcode with one click during the vulnerability exploitation process, rather than obtaining a JSP webshell first and then converting it into a memory shellcode. Therefore, here we need to consider how to directly execute the implantation action of the memory shellcode during the vulnerability exploitation process.

### 2.1 Dynamic Loading and Class Initialization

In most current vulnerability exploits, if you want to execute complex malicious attack logic, you usually use a new URLClassLoader, the current thread's class loader, or a custom class loader to load and initialize malicious class bytecode. In different exploitation scenarios, you can choose different class loaders according to the situation, but sometimes you cannot choose and need to adjust according to the situation:

- Use a new URLClassLoader. If not specified, the system class loader is used as the parent ClassLoader by default, which is the AppClassLoader.
- Use the context class loader of the current thread, generally obtained using `Thread.currentThread().getContextClassLoader()`.
- Create a custom class loader, generally by defining a method for loading classes through bytecode, which is like encapsulating a public `defineClass` method.
- In some exploitation scenarios, it is not possible to customize ClassLoader, such as using BCEL ClassLoader for exploitation.

When using different ClassLoaders to load malicious classes in different situations, different problems will be faced:

- When using the context class loader of the current thread or cannot control the class loader, there may be a situation where the same class name cannot be loaded twice and additional processing is required.
- When using special ClassLoaders such as BCEL ClassLoader, due to the problem of loading across classes, some classes and interfaces need to be accessed and called through pure reflection, which requires a relatively large amount of physical work.

When dynamically loading classes during vulnerability exploitation, it is generally necessary to manually break the parent delegation mechanism and inject the malicious class into the system. Class initialization is closely related to class loading. Usually, in malicious code, some initialization malicious logic will be written, which can generally be written in the static statement block or public parameterless constructor:

- The static statement block is executed once when the class is loaded and only executed once during its lifecycle.
- The public parameterless constructor is called during class initialization, and it is called each time a new class instance is created.

Therefore, you can choose a class loader according to the specific situation and place the malicious logic in an appropriate location.

### 2.2 Echo and Memory Shellcode

After the Goby deserialization implantation extension went online, I enhanced and corrected the exploitation of deserialization vulnerabilities in the vulnerability library. Friends familiar with Goby may know that Goby's detection of vulnerability exploitation is divided into PoC and EXP. When facing native Java deserialization, the original detection and exploitation procedures were:

- PoC uses URLDNS combined with Goby's built-in dnslog platform GodServer for vulnerability detection.
- EXP uses the bytecode of YSOSERIAL, dynamically replaces the hex value of the command execution part, and writes the command execution.

The above logic is used to detect vulnerabilities, which is the way most people detect deserialization vulnerabilities. Technically, there is no problem with this detection method, but in practice, the following problems may be encountered:

1. Due to unstable network or DNSLOG platform, it may not be possible to receive DNSLOG or DNSLOG may have a long delay.
2. Vulnerability exploitation only performs command execution, and it is often impossible to determine whether the vulnerability exploitation is successful or what the result of the vulnerability execution is.

3. In a scenario where there is no outbound network connectivity, it is not possible to perform a reverse shell or execute more advanced actions. In terms of practicality for real-world scenarios, its usability is quite poor.


Therefore, to address the usability issues in practical scenarios, all subsequent updates to the vulnerability exploitation PoCs have adopted echo-based techniques to return the command execution results in the response. As for the exploits (EXP), they are directly injected into the memory as a shellcode, saving a lot of intermediate processes. 

![Image](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjJND2uot9zXCveVhbu2yH9ae3LS0AdZUBQ5epvuAW4jCFZOLNpoQpQCMxP1DsrDoQaAhyBqib63pSg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

### 2.3 In constructing an echo

It involves locating the critical request, searching memory, and other technical points. And to inject a memory shellcode, it is necessary to prepare a highly available memory shellcode for the vulnerability environment. With these technical supports, the problems mentioned above can be solved without the need for third-party dnslog, OOB, etc., directly conducting high-precision detection and utilization of vulnerabilities.

There are many types of vulnerabilities, and there are also many types that can provide arbitrary code execution, such as Java native deserialization vulnerabilities, Fastjson/Jackson/XStream deserialization vulnerabilities, SpEL/Ognl expression injection, etc. However, many situations require additional utilization methods to complete the vulnerability utilization process. Taking advantage of the native deserialization as an example, some modifications of the utilization chain are listed to directly inject memory shellcode.

* The Transformer[] utilization chain is the most classic utilization chain, generally chain a `Runtime.getRuntime().exec()` or` new ProcessBuilder().start() `to execute commands.
  If you want to execute additional functions, you can also use new URLClassLoader().loadClass() to perform remote class loading.
  Without going online, you can write JS to inject malicious classes by using `com.sun.org.apache.bcel.internal.util.ClassLoader.loadClass(), org.mozilla.javascript.DefiningClassLoader().defineClass(), new ScriptEngineManager().getEngineByName("JavaScript").eval() `methods, and one-click utilization of memory shellcode. 

![Image](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjJ2wLadzToQ3afrByDGVp7eZnQXaXwkskLQ7Rm45EV8uddXM11Kn2fia3XNK9I2PHH4YGjgCg3C8cQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

* BeanShell chain, although Bsh supports all Java syntax and many loose writing methods, is ultimately a script language parser. If these writing methods are used or arrays are used in the script, related implementation classes' methods may be called during the deserialization process, and Interpreter objects may be used, which could result in a NullPointerException. Therefore, it is still possible to use ScriptEngineManager to parse JS and execute the memory shellcode.

![Image](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjJ2wLadzToQ3afrByDGVp7enic8CC36KaWibItY4LTdZNIF6UK5TcalXRNpf6BubI2ia8omz2NgST8Ag/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

* In the original version, `C3P0` chain used PoolBackedDataSource for remote class loading to exploit vulnerabilities.
  However, C3P0 can also use Tomcat's getObjectInstance method to call the eval method of ELProcessor for expression injection. This allows injection of memory shellcode through EL expressions, and can also be achieved through other methods such as Groovy, SnakeYaml, etc.

![Image](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjJND2uot9zXCveVhbu2yH9aPQcQbf33o9NpXjX5LdqDljSgoic61a8ibJuY31DZX9fqaAqe3oG0OkVg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

Here are several techniques that link the deserialization exploit chain to memory shell. There are also many other exploit situations that can be “saved by the bell”. Considering the length of the article, further elaboration on these techniques will not be discussed here. 

## **03 Generating In-Memory Shellcode**

After discussing the direction of vulnerability exploitation, we will now discuss some technical details involved in generating in-memory shellcode.

### **3.1 Dynamic Code Generation Techniques**

Considering different vulnerability exploitation points, different exploitation scenarios and requirements, and different personnel's habits and preferences, the content of in-memory shellcode cannot be fixed in practical environments and needs to be dynamically generated based on various configurations.

Therefore, **we use javassist to dynamically generate and write malicious bytecode of in-memory shellcode**. In the process of preparing in-memory shellcode, we will face some requirements:

- The exploitation method of the vulnerability is fixed, such as command execution, commonly used tools such as Behinder, Godzilla, or self-developed webshell interaction tools, and most of them are reusable custom vulnerability exploitation methods;
- In-memory shellcode can customize URL and password, in addition to the common AES key, additional authentication mechanisms can also be set;
- Any in-memory shellcode technique can be freely selected, and any exploitation method can be used to quickly generate dynamically.

Therefore, **I finally abstract the key logic into a same method, whose first two parameters are Request and Response objects. No matter it is command execution, Behinder, Godzilla, etc., their own logic can be injected into this method**. For different middleware, due to different encapsulation and implementation, extra judgment and processing are performed before entering the key logic to make the final processing logic consistent.

For example, below is the core logic of Behinder:

![Image](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjJND2uot9zXCveVhbu2yH9aUL8wR2IbFyEw34uwkPM6TUW3TJ8MPbH3hia0Yc9LDzyNAGEwICSCNQg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

Here is the core logic of Godzilla:

![Image](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjJND2uot9zXCveVhbu2yH9aBHva4rGSc8BbSrqdoTp7y5ugcACsT7IhlcZsJdEcoW3LwmZGNAK9Zg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

Here is the logic of command execution:

![Image](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjJND2uot9zXCveVhbu2yH9aic2iaZ3h0kjhRrfuOLW7lxrMMrnosGtU3z92qJuE7oUMLBdwIRMrOvjg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

After determining the parameters to be used, bytecode can be assembled based on different Memory shellcode types and exploitation methods, with critical methods inserted into malicious classes in sequence, ultimately forming a complete memory shell.

### **3.2 ClassLoader Issues**

As mentioned before, when dynamically loading and initializing a malicious class, it is important to consider the ClassLoader selection. This remains true after the Memory shellcode is loaded, as ClassLoader issues still need to be carefully considered.

In the first case, as the Memory shellcode file itself, the instance should generally be placed in a key position for processing routes, such as in a Map member variable of the global context. In this case, it is necessary to pass a reference to an instance, and register an instance of the shell's own object in a critical position within the system during malicious class initialization.

However, there are exceptions, such as in the Struts2 framework, where the key position stores the class name rather than the class instance. When processing routes, if a mapping is found, the class instance is dynamically created and its execute method is called for processing. Therefore, when injecting a malicious memory shell, the class name and route mapping should not be the only considerations, as the memory shell's own class should also be loaded into the critical context, allowing it to find our injected malicious class during class instantiation.

In terms of exploitation methods, in addition to command execution and feedback, the key logic of a Memory shellcode is still achieved through the transmission of class bytecode. In addition to the previously mentioned URLClassLoader, custom ClassLoader, and thread context ClassLoader, there are still many tricks that can be used, such as:

- Registering a class using java.lang.reflect.Proxy#defineClass0()
- Registering a class directly in the JVM using sun.misc.Unsafe#defineAnonymousClass()
- Using some wrapper classes that may call some uncommon ClassLoaders, such as jdk.nashorn.internal.runtime.ScriptLoader#installClass() and com.sun.naming.internal.VersionHelper#loadClass()

In addition to the above, JavaSec group members have shared some other methods:

- jxxload_help.PathVFSJavaLoader#loadClassFromBytes
- org.python.core.BytecodeLoader1#loadClassFromBytes
- sun.org.mozilla.javascript.internal.DefiningClassLoader#defineClass
- java.security.SecureClassLoader#defineClass
- org.mozilla.classfile.DefiningClassLoader#defineClass

### **3.3 Exploitation Methods**

For Memory shellcode exploitation methods, the three most common types are command execution and feedback, and the Behinder and Godzilla shells, each with their own advantages:

- **Command execution and feedback**: Simple command execution with feedback visible.
- **Behinder and Godzilla shells**: Both provide advanced features that can be selected as needed.

In addition to the typical web shell exploitation methods, the latest trend is the infiltration of tunneling shells. After obtaining a web shell, attackers typically use this machine as a jump point for further intranet penetration. This requires a clear tunneling flow.

Previously, the common approach was to upload a traffic forwarding tool such as FRP to the target server and use this tool for traffic forwarding. If the network layer is not fully port mapped, this can also involve port reuse and other techniques.

However, with a memory shell, a tunneling shell can be easily created with one click, and the appropriate client can be used for direct connection, achieving a true "one-stop" solution.

![Image](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjJND2uot9zXCveVhbu2yH9aDCuQlIoxzvzdoXeKGsp52xr6PqEHlHOLv0nCbP02sGzSmcmTibqyARw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

### **3.4 Agent No File**

The AgentNoFile technology implemented by Master rebeyond provides us with the ability to directly call the JVMTI interface without the need to provide Agent.jar or Agent.so. With this capability, we can inject Agent-type memory shellcode without file landing.

On Linux platform, shellcode is executed by modifying /proc/self/mem. On Windows platform, shellcode is implanted into the process with PID -1 through Java, so as to construct JPLISAgent object and obtain all capabilities of calling Java Agent.

In the BeichenDream's Kcon2021Code project, similar code with this technology idea is also shared.

In the implementation of memory shellcode, a Javassist dependent jar is injected into the target environment without landing, and the target critical class is dynamically modified to inject malicious logic, which realizes the dynamic modification of Agent shellcode. For example, the following figure shows the logic of hooking doFilter method of ApplicationFilterChain, injecting Behinder memory shellcode, and dumping class from the server.

![Image](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjJ2wLadzToQ3afrByDGVp7elDDLpWVF28ICp6Fk3rmKGLCjLHtmS2ZAXWArmYzWj0ic5t1xqWBzfIA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

## **04 Usage of Memory Shellcode**

The problem of exploiting vulnerabilities to directly inject memory shellcodes and the generation and utilization methods of memory shellcodes have been resolved. The next problem to be addressed is the issues encountered during the use of memory shellcodes.

As mentioned in previous articles, the main purpose of the Memory shellcode technology is to combat the problem of security protection devices detecting and alarming against landed files. Therefore, since its inception, Memory shellcode technology has faced and shouldered the responsibility and mission of confronting various protection capabilities.

### **4.1 Bypassing Security Protections**

The first challenge is **bypassing traffic-side devices**. This is actually the traffic characteristics of the communication protocol between the WebShell management side and the memory shell. Since AES encryption and decryption are commonly used, with a small number of cases using DES encryption and decryption, and there are regular behaviors, such as sending several packets when connecting to the WebShell, there are some means to detect webshell connections based on these two factors. Therefore, whether it is the Behinder or Godzilla, if they have not been customized, their basic traffic characteristics will be detected.

However, basically everyone has the habit of customization, so the traffic layer characteristics are still not easy to be uniformly protected, and the latest Behinder client already supports custom communication protocol encryption and decryption programs. This allows attackers to disguise Behinder traffic as similar to business data traffic, such as Restful API return data, or similar base64 image resource return data.

The second challenge is **bypassing host-level protections**. At the host level, there may be some host-level defenses such as EDR devices, which may monitor Java process calls to system resources. However, most of the time, it is almost impossible for this level of defense to determine whether Java-level operations are sensitive operations.

Finally, there is **bypassing Java-level protections**. At the Java level, there may be some RASP products or custom security rules defenses. These defenses intercept suspicious behaviors based on stack or behavior, and hook at the position where some sensitive functions are executed.

At this point, we can bypass these defenses through reflection. Whether it is to call deeper code or even native methods through reflection, or to reflectively obtain objects that encapsulate specific methods in the system for execution, the purpose is to disrupt the stack or behavior call chain, making Java-level defense unable to determine whether you are performing malicious operations or system behaviors, thus bypassing the detection logic.

For example, bypassing command execution defense through reflection to call native methods:

![Image](https://mmbiz.qpic.cn/mmbiz_jpg/GGOWG0fficjJND2uot9zXCveVhbu2yH9abe6GZEico8NrFl3iavoBEZqUibsD1kx4hnNYON2YRPOvzibAu3toiaRUkJA/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1)

Or use messy reflection to make the call chain difficult to trace:

![Image](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjJND2uot9zXCveVhbu2yH9aa35QKMmiazLY5rHTQQe6dqBGH8ZSpIbBFSickSh9cM8icRmwFunu948qg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

Creating malicious classes using APIs like `unsafe` can also bypass certain security defenses:

![Image](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjJND2uot9zXCveVhbu2yH9a3x36cPNjzViau2AfUJUbAnr1lNuatx4Eo35gxufeLnZeuUxPtOQcshQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

### **4.2 Anti-detection**

As mentioned in previous memory shellcode articles, many tools have provided detection methods to scan specific locations to check for the presence of memory shellcode. At this time, the check will include some dimension judgments. Similarly, we need to perform certain processing on these dimensions to prevent detection, for example:

1. **Detection of malicious class names and package names**: For some defense measures, loading of known malicious package names and class names will be prohibited. Therefore, we use dynamic splicing and generation of malicious class package names to confuse the defense system or administrator.

![Image](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjJND2uot9zXCveVhbu2yH9aAaKZyZ9I3knF74py3O6Dr0EaQ6RCLquDEGgzNeRqM3oMaAickFdNQZQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

2. **Detection of whether files are written to disk from ClassLoader**: The detection logic can be bypassed by using a custom ClassLoader to carry false information or loading malicious classes using the system class loader with an empty class loader for the malicious class.

![Image](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjJ2wLadzToQ3afrByDGVp7eVxibpibR7Oy6DozFGv98sVI8PtqSqiaoN0psibgDQ1qlTXiabAHyrFGyp1Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

3. **Detection of critical positions in the system**: Some detection tools can obtain information about critical positions and assist in manual inspection. For example, some tools obtain all Filter-type memory shellcode in the system and display them. At this time, it is possible to evade detection by exploring unconventional memory shellcode. As mentioned in the PPT I shared earlier about JavaWeb memory shellcode, all components that use the chain of responsibility design pattern in the web request processing process can be used as directions for exploring and utilizing memory shellcode. Therefore, it is not difficult to explore a new type of memory shellcode in various web middleware.

![Image](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjJND2uot9zXCveVhbu2yH9aSkQiaAe3YibPTvmsHCs6vomJBpZZbkOmNF86ckgQ7AGJjVgF2QYqgKTA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

4. Many tools offer the ability to dump the class, allowing for troubleshooting by dumping the class bytecode in memory. Therefore, it is possible to modify the cache of relevant information in the InstanceKlass data structure of the Java class in the JVM, such as _cached_class_file, to deceive and hide by making the dumped class not contain dangerous code.
5. Some RASPs also use redefineClasses to set the critical method content of malicious classes and functions to empty, in order to clear the memory shellcode in the running system. At this point, it is possible to make it fail by modifying the function modifiers, adding member variables, methods, etc. of the malicious class, as redefineClasses does not allow changes in class structure and signatures.
6. Currently, most of the methods for detecting and defending against memory shellcode are implemented through Java Agent technology. Therefore, preventing new Agent injections is also a key strategy for preventing detection. As mentioned in the first article, blocking the communication between JVM processes by deleting the java pid file and preventing the loading of subsequent ClassFileTransformers can prevent the loading of other Java Agents and prevent detection.

### **4.3 Disappear Without a Trace**

First of all, since memory shellcode have reached the point of not leaving files behind, is there anything else that can be done to hide themselves again? The answer is yes.

That is, clearing the access logs of middleware. When making access requests, middleware records logs, which are usually used as the basis for subsequent reviews and emergency responses. If access logs can be cleared during memory shellcode access, wouldn't that be anonymous browsing?

With the idea in place, the execution is simple, which is to find the component responsible for logging in the middleware and clear it. Taking Tomcat as an example.

![Image](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjJND2uot9zXCveVhbu2yH9asQZxVBnSe8TkR0YzQV4OSxc5aicPNfVmmOf7TibV2tp0qiciaWyicBPABqQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1)

### **4.4 Persistence**

The final issue is the issue of persistence, which needs to consider whether the injection of memory shellcode can be restored after service restart or even operating system restart:

- For Java, Java shutdown hook can be used for landing and other operations of memory shellcode. If the target environment is Tomcat, JSP files can be written in the resource directory of Jar package, etc.;
- If the target environment may be killed by -9, a "daemon process" can be started to monitor the Java process on the server;
- For operating system restart, critical malicious operations can be registered as timed tasks in advance to achieve persistence.

Since these actions are an extension of memory shellcode technology and may involve tampering and landing of Jar packages and resource files in order to achieve persistence, which is somewhat contrary to the original intention of using memory shellcode, this part will not be discussed further, and we look forward to more elegant ideas.



## 05 Summary

The above section briefly lists some technical issues and solutions encountered in practical use of memory shellcode technology. After researching and resolving the above techniques, there should be no problem in using memory shellcode quickly in practice.

Although we are discussing JavaWeb memory shellcode technology, it can be seen that the thinking and technology of the countermeasures have already extended beyond the Java layer to the native layer and memory level. This is still a drop in the bucket in practical use. In actual use, due to differences in operating systems, middleware versions, JDK distributions and versions, security restrictions, security protection and other complex situations, there will be various difficulties. Therefore, more research and debugging, and accumulation of ideas can enable efficient and fast use of memory shellcode in practical use.

In the face of memory shellcode technology, it is superficially a technical confrontation, but in fact it is a confrontation between people and people, thinking and thinking. I throw out some ideas here, hoping to inspire more ingenious ideas, and welcome everyone to discuss.
