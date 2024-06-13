package org.fupo.javaeasyscan;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

/**
 * @author novy
 * @version 1.0
 * @createDate 2024/6/13 14:53
 **/
public class CodeAuditMain {

    public static void main(String[] args) throws Exception {
        // 项目根目录
        File rootDir = new File(args[0]);
        // 存储所有找到的MyBatis XML文件
        List<File> xmlFiles = new ArrayList<>();
        // 递归扫描目录
        collectXmlFiles(rootDir, xmlFiles);

        // 存储XML文件中解析到的Mapper接口名及其文件路径
        Map<String, String> namespaceToPathMap = new HashMap<>();
        Map<String, List<String>> namespaceToVulnerableMethodsMap = new HashMap<>();

        // 解析每个XML文件，查找SQL注入点和namespace
        for (File xmlFile : xmlFiles) {
            scanMyBatisXML(xmlFile, namespaceToPathMap, namespaceToVulnerableMethodsMap);
        }

        // 递归扫描目录，查找所有Java文件
        List<File> javaFiles = new ArrayList<>();
        collectJavaFiles(rootDir, javaFiles);

        // 查找并输出Mapper接口文件中存在漏洞的方法
        for (Map.Entry<String, String> entry : namespaceToPathMap.entrySet()) {
            String namespace = entry.getKey();
            String xmlFilePath = entry.getValue();
            List<String> vulnerableMethods = namespaceToVulnerableMethodsMap.get(namespace);
            findMapperInterface(namespace, xmlFilePath, javaFiles, vulnerableMethods);
        }
    }

    // 递归扫描目录，收集所有MyBatis XML文件
    public static void collectXmlFiles(File dir, List<File> xmlFiles) {
        if (dir.isDirectory()) {
            for (File file : dir.listFiles()) {
                collectXmlFiles(file, xmlFiles);
            }
        } else {
            if (dir.getName().endsWith(".xml")) {
                xmlFiles.add(dir);
            }
        }
    }

    // 递归扫描目录，收集所有Java文件
    public static void collectJavaFiles(File dir, List<File> javaFiles) {
        if (dir.isDirectory()) {
            for (File file : dir.listFiles()) {
                collectJavaFiles(file, javaFiles);
            }
        } else {
            if (dir.getName().endsWith(".java")) {
                javaFiles.add(dir);
            }
        }
    }

    // 扫描单个MyBatis XML文件，查找SQL注入点和namespace
    public static void scanMyBatisXML(File xmlFile, Map<String, String> namespaceToPathMap, Map<String, List<String>> namespaceToVulnerableMethodsMap) throws Exception {
        // 使用SAX解析XML文件，获取每个节点的行号
        XMLInputFactory factory = XMLInputFactory.newInstance();
        XMLStreamReader reader = factory.createXMLStreamReader(new FileInputStream(xmlFile));

        String namespace = null;

        while (reader.hasNext()) {
            int event = reader.next();
            if (event == XMLStreamConstants.START_ELEMENT) {
                String elementName = reader.getLocalName();
                if ("mapper".equals(elementName)) {
                    namespace = reader.getAttributeValue(null, "namespace");
                    if (namespace != null) {
                        namespaceToPathMap.put(namespace, xmlFile.getAbsolutePath());
                        namespaceToVulnerableMethodsMap.put(namespace, new ArrayList<>());
                    }
                } else if (Arrays.asList("select", "insert", "update", "delete").contains(elementName)) {
                    String id = reader.getAttributeValue(null, "id");
                    String sql = getElementText(reader);
                    int lineNumber = reader.getLocation().getLineNumber();

                    // 检查是否存在潜在的SQL注入点
                    if (sql.contains("${")) {
                        System.out.printf("%s 的 %s 方法存在注入，在第 %d 行%n", xmlFile.getName(), id, lineNumber);
                        if (namespace != null) {
                            namespaceToVulnerableMethodsMap.get(namespace).add(id);
                        }
                    }
                }
            }
        }
    }

    // 获取XML元素的文本内容
    private static String getElementText(XMLStreamReader reader) throws XMLStreamException {
        StringBuilder content = new StringBuilder();
        while (reader.hasNext()) {
            int event = reader.next();
            if (event == XMLStreamConstants.CHARACTERS) {
                content.append(reader.getText());
            } else if (event == XMLStreamConstants.END_ELEMENT) {
                break;
            }
        }
        return content.toString();
    }

    // 查找并输出Mapper接口文件中存在漏洞的方法
    public static void findMapperInterface(String namespace, String xmlFilePath, List<File> javaFiles, List<String> vulnerableMethods) {
        String interfaceName = namespace.substring(namespace.lastIndexOf('.') + 1) + ".java";

        for (File javaFile : javaFiles) {
            if (javaFile.getName().equals(interfaceName)) {
                boolean foundVulnerableMethod = false;
                List<String> lines;
                try {
                    lines = Files.readAllLines(javaFile.toPath());
                } catch (IOException e) {
                    e.printStackTrace();
                    continue;
                }

                for (String methodName : vulnerableMethods) {
                    for (int i = 0; i < lines.size(); i++) {
                        String line = lines.get(i).trim();
                        if (line.startsWith("public") && line.contains(methodName + "(")) {
                            if (!foundVulnerableMethod) {
                                System.out.printf("%s 对应的接口文件：%s%n", Paths.get(xmlFilePath).getFileName(), javaFile.getAbsolutePath());
                                foundVulnerableMethod = true;
                            }
                        }
                    }
                }
                break; // 找到匹配的接口文件后退出循环
            }
        }
    }
}
