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
    private static String result1;
    private static String sqlrep;
    public static void main(String[] args) throws Exception {
        // 项目根目录
        File rootDir = new File(args[0]);
        // 存储所有找到的MyBatis XML文件
        List<File> xmlFiles = new ArrayList<>();
        // 递归扫描目录
        collectXmlFiles(rootDir, xmlFiles);

        // 存储XML文件中解析到的Mapper接口名及其文件路径
        Map<String, String> namespaceToPathMap = new HashMap<>();

        // 解析每个XML文件，查找SQL注入点和namespace
        for (File xmlFile : xmlFiles) {
            result1 = scanMyBatisXML(xmlFile, namespaceToPathMap);
        }

        // 递归扫描目录，查找所有Java文件
        List<File> javaFiles = new ArrayList<>();
        collectJavaFiles(rootDir, javaFiles);

        // 查找并输出Mapper接口文件中存在漏洞的方法
        for (Map.Entry<String, String> entry : namespaceToPathMap.entrySet()) {
            String namespace = entry.getKey();
            String xmlFilePath = entry.getValue();
            findMapperInterface(namespace, xmlFilePath, javaFiles, result1);
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
    public static String scanMyBatisXML(File xmlFile, Map<String, String> namespaceToPathMap) throws Exception {
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
                    }
                } else if (Arrays.asList("select", "insert", "update", "delete").contains(elementName)) {
                    String id = reader.getAttributeValue(null, "id");
                    String sql = getElementText(reader);
                    int lineNumber = reader.getLocation().getLineNumber();

                    // 检查是否存在潜在的SQL注入点
                    if (sql.contains("${")) {
                        sqlrep = xmlFile.getName() + "的 " + id + " 方法存在注入，在第" + lineNumber + "行，";
                    }
                }
            }
        }
        return sqlrep;
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
    public static void findMapperInterface(String namespace, String xmlFilePath, List<File> javaFiles,String result1) {
        String interfaceName = namespace.substring(namespace.lastIndexOf('.') + 1) + ".java";
        String mapperFileName = Paths.get(xmlFilePath).getFileName().toString().replace(".xml", ".java");

        for (File javaFile : javaFiles) {
            if (javaFile.getName().equals(interfaceName) && javaFile.getName().equals(mapperFileName)) {
                try {
                    List<String> lines = Files.readAllLines(javaFile.toPath());
                    for (int i = 0; i < lines.size(); i++) {
                        String line = lines.get(i);
                        for (String methodName : getVulnerableMethods(xmlFilePath)) {
                            if (line.contains(methodName)) {
                               System.out.println(result1 + "接口：" + javaFile.getName());
                            }
                        }
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
                break; // 找到匹配的接口文件后退出循环
            }
        }
    }

    // 获取存在漏洞的方法名（从XML文件解析的SQL注入点）
    private static List<String> getVulnerableMethods(String xmlFilePath) {
        List<String> vulnerableMethods = new ArrayList<>();
        try {
            XMLInputFactory factory = XMLInputFactory.newInstance();
            XMLStreamReader reader = factory.createXMLStreamReader(new FileInputStream(xmlFilePath));

            while (reader.hasNext()) {
                int event = reader.next();
                if (event == XMLStreamConstants.START_ELEMENT) {
                    String elementName = reader.getLocalName();
                    if (Arrays.asList("select", "insert", "update", "delete").contains(elementName)) {
                        String id = reader.getAttributeValue(null, "id");
                        String sql = getElementText(reader);
                        if (sql.contains("${")) {
                            vulnerableMethods.add(id);
                        }
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return vulnerableMethods;
    }
}
