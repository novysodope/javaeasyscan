package org.fupo.javaeasyscan;

import com.github.javaparser.symbolsolver.JavaSymbolSolver;
import org.w3c.dom.*;
import javax.xml.parsers.*;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.*;
import java.util.*;
import java.util.stream.Collectors;
import com.github.javaparser.*;
import com.github.javaparser.ast.*;
import com.github.javaparser.ast.body.*;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.visitor.*;
import com.github.javaparser.resolution.declarations.*;
import com.github.javaparser.symbolsolver.javaparsermodel.JavaParserFacade;
import com.github.javaparser.symbolsolver.model.resolution.TypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.*;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

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

        // 解析每个XML文件
        for (File xmlFile : xmlFiles) {
            scanMyBatisXML(xmlFile);
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

    // 扫描单个MyBatis XML文件，查找SQL注入点
    public static void scanMyBatisXML(File xmlFile) throws Exception {
        // 使用SAX解析XML文件，获取每个节点的行号
        XMLInputFactory factory = XMLInputFactory.newInstance();
        XMLStreamReader reader = factory.createXMLStreamReader(new FileInputStream(xmlFile));

        while (reader.hasNext()) {
            int event = reader.next();
            if (event == XMLStreamConstants.START_ELEMENT) {
                String elementName = reader.getLocalName();
                if (Arrays.asList("select", "insert", "update", "delete").contains(elementName)) {
                    String id = reader.getAttributeValue(null, "id");
                    String sql = getElementText(reader);
                    int lineNumber = reader.getLocation().getLineNumber();

                    // 检查是否存在潜在的SQL注入点
                    if (sql.contains("${")) {
                        System.out.printf("%s 的 %s 方法存在注入，在第 %d 行%n", xmlFile.getName(), id, lineNumber);
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
}
