# The king of shell Javaweb Memory Shell-Cognitive Section

>  "Introduction: Hello everyone, I am su18. Whether it's personal blogs or communities, it's been a long time since I wrote technical articles. There are many reasons for this, such as time, energy, and mindset. But I am relatively active in the open source community. Due to work needs, I wrote and open-sourced a project called ysuserial in June this year. Based on the original project, I optimized and processed it, and added many new features.
>
>  In the following days, I periodically implemented and summarized some of the content I saw, learned, and researched online in this project. In addition to serialization-related technologies, I also emphasized adding the function of directly injecting memory shell into the project. Currently, the project supports various common memory shell. Although the publicly available code is not particularly in-depth in terms of utilization, it is very versatile and comprehensive, and has been tested in multiple versions.
>
>  Regarding memory shell-related technical articles, I have written two articles "JavaWeb memory shell First Week Pass Guide" and "JavaWeb memory shell Second Week Pass Guide" on my personal blog, which technically introduced the implementation of several common memory shell. In fact, this series can still write many articles and can continue to go deeper. Last year, I also wrote about the killing and defense projects of memory shell from the perspective of RASP, and shared some PPTs.
>
>  Later, as time passed, I saw many mentors, vendors, and platforms using different memory shell implementations in actual combat, including different middleware, frameworks, CMS, and other available memory shell. I found that everyone is not limited to existing patterns, their thinking diverges, and they have done a lot of DIY from implantation, utilization, and traffic.
>
>  Later, I realized that the use of memory shell has become more and more popular, and there are more and more related articles. However, even so, many mentors still feel a bit vague about the related concepts when consulting me about related issues, and there are still some high thresholds in the use of technology. Therefore, this time I plan to approach the topic from some new angles and talk about related content again."



# 01 Introduction

If we were to classify webshells by level, JavaWeb memory injection is undoubtedly the king of shells at present. What makes it so special? Traditional webshell backdoors, no matter how much effort is put into hiding or how they are disguised, are unable to persist in the target system under existing defense measures. Some simple examples of defense measures include: For terminal security: file monitoring, anti-tampering, and EDR; For backdoors: webshell detection and traffic monitoring; For the network layer: firewalls to prevent reverse connections, and reverse proxy systems to hide real IPs; and so on. Currently, mainstream defense measures have a static detection rate of over 90% for webshells and are even ineffective in some environments. Defense teams can respond quickly in emergency situations. Due to these limitations, memory injection techniques have emerged and developed rapidly. Memory-based attack methods such as fileless attacks, memory webshells, and process injection are gaining more and more attention from experts and have already made their mark in real-world environments. It can be said without exaggeration that memory injection-related technologies will be essential security skills for future penetration testers.

This article, titled "Javaweb Memory Shell [Cognitive Section]," explains why Java is used.

1. For enterprise users, Java is the programming language with the widest range of applications, the most extensive ecosystem, and the largest user base. Therefore, the middleware developed using Java is also the most extensive and has the most users.
2. Java security is an industry with a lot of attention and research. This article will help readers quickly understand and recognize what memory injection is, what JavaWeb memory injection is, and list several cases to assist readers in comprehension from theoretical and conceptual perspectives.

# 02 Evolution of Concepts

In 2017, n1nty published an article titled "Tomcat Source Code Debugging Notes - Invisible Shell" on his personal WeChat account, which proposed two techniques for hiding webshells. Today, this article has just over 1,000 views, but it is indeed one of the earliest articles to propose and implement this technique.

Before that, I also discovered "Java Timer Backdoor" published by Yuan Zhang in 2014 on his personal blog. I found that in some cases, even if the JSP file is deleted, the code in it will still reside in the program and continue to execute.

I believe that during this period, many experts have also discovered and used similar techniques to achieve the goal of executing code logic without the need for a JSP shell file to exist on the server for a long time.

This concept did not receive full attention in the security industry, and only a few researchers in the community were exploring and exchanging related implementations until the update of ice scorpion Behinder_v3.0 Beta 7 implemented memory shell with java agent type, bringing this technology into the public view.

As the technology continues to evolve, more and more people are using the JavaWeb memory shell technique, and the development of technology is becoming increasingly complex. At the same time, security vendors for traffic detection, terminal security, RASP, and other security measures have also begun to detect and defend against memory shell, leading to the emergence of various bypass techniques.

Discussion of this technology is much more extensive in China than in foreign countries, which may be due to the habits of Chinese security personnel in using webshell management software. That is to say, in this part of the technical field, research and accumulation in China is ahead of the international community. However, the practical use of memory shell technology is still in its infancy, and there is still great potential for technological development in the future.

The attack and defense of memory shell are still constantly being upgraded and developed, and it is believed that more interesting techniques will emerge.

# 03 Classification of memory shell

So far, there have been many ways of utilizing memory shell discussed publicly on the Internet. This article roughly categorizes them according to the implementation techniques of memory shell. They can be roughly divided into the following categories:

![https://github.com/gobysec/Memory-Shell/blob/main/Memory%20shell.png](https://github.com/gobysec/Memory-Shell/blob/main/Memory%20shell.png)

- **Traditional Web Application memory shell**: This type of memory shell uses basic Servlet-API to dynamically register memory shell, and is the most classic type of memory shell that has been extended to adapt to various middleware.
- **Framework memory shell**: In addition to traditional Servlet projects, there are more and more projects developed using Spring family, and Spring-MVC has implemented related routing registration and lookup logic, and uses interceptors for filtering, which is similar in design to Servlet-Filter.
- **Middleware memory shell**: In many of the middleware's functional implementations, the responsibility chain pattern, similar to Filter-FilterChain, can be used to implement memory shell. Due to the industry's extensive research on Tomcat, most of the technical implementations and explorations are targeted at Tomcat, but there is also considerable exploration space for other middleware.
- **Other memory shell**: There are also some unconventional ideas that can be used in memory shell implementations, such as WebSocket protocol.
- Agent memory shell: This is an implementation method that uses Java Agent technology to implant memory shell logic.

However, in reality, the depth and breadth of memory shell are not limited to the above. There are still many ideas that can be used to extend memory shell:

- **For Agent-type memory shell, many positions can be hooked, such as various SPI implementations, which can take over the entire JVM and obtain data.**
- **In addition to web-based memory shell, various protocols can be used as communication channels for memory shell, such as grpc, jmx, jpda, or encapsulated in multiple layers of protocols.**
- **For various middleware/frameworks, various memory shell utilization methods can be excavated by utilizing their design patterns.**



In addition to classifying memory shell by their implementation method, they can also be classified by their utilization methods, such as the IceRat horse, Godzilla horse, AntSword horse, command echo horse, traffic tunnel horse, and so on.

# 04 Practical Discussion

After conducting research, I found that there are many people who use memory shell technology in practical operations. The main reasons for using memory shell, which are also the advantages of memory shell, are as follows:


After conducting some research, I found that there are many people using memory shell in practice. The main reasons for using memory shell and their advantages are as follows:

- **Unable to rebound shell due to network issues;**
- **Internal hosts exposed web ports through reverse proxies;**
- **There are defense measures such as anti-tampering and directory monitoring on the server, which prohibit file writing;**
- **There are other monitoring methods on the server, and alarms will be triggered after the horse is written, which requires manual response;**
- **Springboot and other frameworks are used, which cannot parse traditional webshells;**
- **Impressed by the mysteriousness of memory shell.**

However, the disadvantages of memory shell are also obvious:

- They will be invalidated after service restarts;
- The location of traditional memory shell is relatively fixed, and there are related detection techniques that can be used to detect them.

Nevertheless, for most online services, the requirement for high availability usually means that service restarts are not frequent. Coupled with many advantages, memory shell have become the preferred method for attackers to maintain webshells.

Attackers usually use webshell management tools such as IceBug and Godzilla to generate malicious logic for memory shell, which can be used for subsequent functions. Of course, they can also use logic such as ReGeorg to establish an intranet tunnel or simple command feedback.

The choice and use of memory shell are a matter of personal preference. Some people prefer Servlet-API memory shell, considering them to be more native; some prefer WebSocket memory shell, considering them to be more innovative; and some prefer Agent-type memory shell, considering them to be more versatile. Regardless of the type used, the impact on the actual environment needs to be considered. For example, Filter-type memory shell are generally placed at the beginning and end of the FilterChain. If they handle requests for "/*", the impact of subsequent Filter processing in the FilterChain needs to be considered. If using Agent-type memory shell, the possibility of JVM Crush caused by their complex logic needs to be considered.

Overall, **the most popular memory shell are Servlet-API and Agent-type**, possibly because these related technologies have been fully implemented and made public, while only a small number of people use other types of memory shell in practice.

In addition to the impact of network and application environments, memory shell also need to consider compatibility issues. For a technology, the technical details may change in different versions of the framework or components. Therefore, to implement an excellent memory shell, it is necessary to be compatible with different versions of components and undergo practical testing.

In the implementation of attack and defense, I found that the more niche and non-mainstream the memory shell implementation method is, the easier it is to evade defense detection.



# **05 Technical Offensive and Defensive Extension**

The concept of memory shell has been popular for several years, and the offensive and defensive of memory shell has naturally been contested many times.

- First, let's take a look at the iteration of defense measures:

> LandGrey released the copagent project in 2020, which is based on Java Agent technology to find subclasses of key classes, key annotation classes, and mark classes with malicious package names. Then, these classes are dumped out and risk keywords are matched.

> c0ny1 also released the java-memshell-scanner project, which uses Tomcat API to find information in key locations (Servlet/Filter), and checks for memory shell based on ClassLoader to determine whether it is on the disk, class name (package name), and other information. It also supports dumping classes from memory for manual analysis.

> potats0 solved the problem of unable to obtain the class bytecode processed by the class using redefineClasses through sa-jdi.jar.

> There are also masters who proposed to use the mbean-based filter/servlet risk class recognition dimension to search for memory shell.

> These defense measures locate key classes in the target system and identify risks from multiple dimensions to detect memory shell.

- Next, let's take a look at the means of bypassing detection:

> By deleting the /tmp/.java_pid+{pid} file, Behinder prevents JVM process communication and prohibits Agent loading from being detected.

> ZhouYu prevents other Java Agents from loading by blocking the loading of subsequent ClassFileTransformers to prevent detection and killing.

> Glassy shared the method of bypassing memory shell detection by loading malicious classes through Bootstrap ClassLoader.

> Behinder and Godzilla authors have also made technical breakthroughs in Agent Self Attach and fileless landing injection of Agent memory shell, which can be injected into Agent memory shell without landing files.

The bypassing means is based on the transparency of the detection method and bypasses its key logic, making the detection means ineffective.

There are many related means and ideas, which are not listed here. In addition to targeted killing of memory shell, memory shell also faces problems of conventional defense, such as feature defense of memory shell interaction in traffic layer, defense of malicious operations in host or code layer, and so on. WAF, RASP, EDR, and HIDS have become stumbling blocks for implanting memory shell in actual combat.

In addition to open source projects, major security vendors have also released detection and killing projects for memory shell, and it is necessary to bypass them in actual combat.

But it is certain that no matter what kind of defensive technology, in the increasingly bottom-layer memory offensive and defensive and increasingly dynamic attack methods, there will be difficulties. As the saying goes, the higher the level of technology, the higher the level of devil.

# 06 Case Studies

In both offensive and defensive operations, memory-resident malware techniques have been used repeatedly and both sides have clashed over this technique. Here are a few real-world case studies.

### Case One: A certain friend's NC deserialization vulnerability

During the attack process, a deserialization vulnerability was found in a certain friend's NC system. Testing revealed that URLDNS could receive logs, but a shell could not be bounced back, and it was suspected that the target environment could not access the Internet.

After several tests, it was found that file writing vulnerabilities could be attempted, but when the file was landed, it would be quickly killed. It was speculated that there was a file directory monitoring means, and if a new file was generated, the device would sound an alarm, and the defender would kill it.

Later, after local testing and research, a memory-resident malware was directly injected through the deserialization vulnerability. The target system's devices had no alarms, and the defenders were unaware, successfully taking down the target and penetrating the internal network.

### Case Two: springboot + shiro 550 does not access the Internet

The target was found to be a self-developed application system that used the springboot framework and shiro for authentication. After testing, it was discovered that the system was using a lower version of shiro and the default AES encryption key was used. So, an attack was attempted using the shiro 550 CB chain, but the system did not access the Internet, and a reverse connection could not be made.

At the same time, the program used springboot and was started in the form of a Jar file, without a directory for parsing JSP, making it impossible to getshell by executing commands in the form of writing JSP webshell.

To persist and further attack, after many tests, a Spring Interceptor-based memory-resident malware was eventually used to obtain Web server privileges.

There are many similar cases like this, and in various hostile environments, memory-resident malware can solve many practical problems.

To provide a clearer demonstration of the role of memory-resident malware, here is a simple demonstration using the latest version of OpenRASP (daily persecution) to demonstrate the bypass ability of memory-resident malware.

<video src="https://github.com/gobysec/Memory-Shell/blob/main/memory%20shell.mp4"></video>


# 07 Question

There are still many details to be studied regarding memory injection, which promotes the continuous improvement of memory injection attack and defense techniques.

In the field of memory injection, the development of attack techniques is far faster than that of defense techniques. Attackers only need to focus on implementation without considering the consequences, while defenders need to consider the impact on the actual environment.

Currently, most exploit tools used by people provide partial implementation of memory injection, such as JNDI injection exploit tools, Shiro exploit tools, Weblogic exploit tools, and so on. However, these are limited to a single type of exploit. For other environments, such as certain frameworks or CMS vulnerabilities, extensive research and debugging are still required to directly inject a certain type of memory injection.

The commonly used webshell management tools, such as Godzilla, Cobalt Strike, and AntSword, all provide a one-click injection of memory injection and are technically excellent. However, they also have a fatal logical "problem":

Doesn't the requirement of having a file-type webshell before implanting memory injection contradict the original intention of using memory injection techniques?

This is actually worth our consideration. Can we directly inject memory injection for common types of exploit, rather than using webshell management software through landing JSP for intermediate transfer? Or are there more general means or frameworks to quickly inject and utilize memory injection in attacks?

I will discuss this question in detail in the following sections.

# **08 REFERENCE**

1. 2017 - Tomcat 源代码调试笔记 - 看不见的 Shell
2. 2014 - Java Timer 后门 (https://www.javaweb.org/?p=544）
3. 2021 - 冰蝎 Beta 7（https://github.com/rebeyond/Behinder/releases/tag/Behinder_v3.0_Beta_7）
4. 2020 - copagent（https://github.com/LandGrey/copagent）
5. 2020 - java-memshell-scanner（https://github.com/c0ny1/java-memshell-scanner）
6. 2021 - ZhouYu（https://github.com/threedr3am/ZhouYu）
7. 2021 - aLIEz（https://github.com/r00t4dm/aLIEz）
8. 2022 - RASP攻防下的黑魔法
9. 2021 - Java内存攻击技术漫谈（https://xz.aliyun.com/t/10075）
10. 2022 - 论如何优雅的注入Java Agent内存马（https://xz.aliyun.com/t/11640）
11. 2021 - JavaWeb 内存马一周目通关攻略（https://su18.org/post/memory-shell/）
12. 2021 - JavaWeb 内存马二周目通关攻略（https://su18.org/post/memory-shell-2/）
13. 2021 - ShiroAttack2（https://github.com/SummerSec/ShiroAttack2）
14. 2021 - JNDIExploit（https://github.com/feihong-cs/JNDIExploit）
15. 2022 - ysuserial（https://github.com/su18/ysoserial）
16. 2020 - MemoryShell（https://github.com/su18/MemoryShell）



**[Goby Official URL](https://gobies.org/)** 

1. GitHub issue: https://github.com/gobysec/Goby/issues
2. Telegram Group: http://t.me/gobies (Group benefits: enjoy the version update 1 month in advance) 
3. Telegram Channel: https://t.me/joinchat/ENkApMqOonRhZjFl (Channel benefits: enjoy the version update 1 month in advance) 
4. WeChat Group: First add my personal WeChat: **gobyteam**, I will add everyone to the official WeChat group of Goby. (Group benefits: enjoy the version update 1 month in advance) **
