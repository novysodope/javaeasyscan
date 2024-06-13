package org.fupo.javaeasyscan;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import org.codehaus.stax2.XMLInputFactory2;
import org.codehaus.stax2.XMLStreamReader2;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

/**
 * @author novy
 * @version 1.0
 * @createDate 2024/6/13 14:53
 **/
public class CodeAuditMain {
    private static final Logger logger = LoggerFactory.getLogger(CodeAuditMain.class);
    private static final JavaParser javaParser = new JavaParser();
    private static final Map<String, Set<String>> methodCallMap = new HashMap<>();
    private static final Set<String> potentialSQLInjectionPoints = new HashSet<>();

    public static void main(String[] args) {
        if (args.length < 1) {
            logger.error("Usage: java CodeAuditTool <path to project root>");
            return;
        }

        String projectRoot = args[0];
        try {
            // 扫描XML文件
            Files.walk(Paths.get(projectRoot))
                    .filter(Files::isRegularFile)
                    .filter(path -> path.toString().endsWith(".xml"))
                    .forEach(CodeAuditMain::parseAndAnalyzeXMLFile);

            // 扫描Java文件
            Files.walk(Paths.get(projectRoot))
                    .filter(Files::isRegularFile)
                    .filter(path -> path.toString().endsWith(".java"))
                    .forEach(CodeAuditMain::parseAndAnalyzeJavaFile);

            // 输出潜在的SQL注入点
            potentialSQLInjectionPoints.forEach(logger::warn);

        } catch (IOException e) {
            logger.error("Failed to scan project: " + projectRoot, e);
        }
    }

    private static void parseAndAnalyzeXMLFile(Path path) {
        try (FileInputStream in = new FileInputStream(path.toFile())) {
            XMLInputFactory factory = XMLInputFactory2.newInstance();
            XMLStreamReader2 reader = (XMLStreamReader2) factory.createXMLStreamReader(in);

            String namespace = null;
            while (reader.hasNext()) {
                int eventType = reader.next();
                if (eventType == XMLStreamReader.START_ELEMENT) {
                    if (reader.getLocalName().equals("mapper")) {
                        namespace = reader.getAttributeValue(null, "namespace");
                    } else if (reader.getLocalName().matches("select|update|delete|insert")) {
                        String id = reader.getAttributeValue(null, "id");
                        StringBuilder sql = new StringBuilder();
                        int lineNumber = reader.getLocation().getLineNumber();

                        while (reader.hasNext()) {
                            eventType = reader.next();
                            if (eventType == XMLStreamReader.CHARACTERS || eventType == XMLStreamReader.CDATA) {
                                sql.append(reader.getText());
                            } else if (eventType == XMLStreamReader.END_ELEMENT && reader.getLocalName().matches("select|update|delete|insert")) {
                                break;
                            }
                        }

                        if (sql.toString().contains("${")) {
                            String mapperMethod = namespace + "." + id;
                            potentialSQLInjectionPoints.add("Potential SQL injection in XML: " + path + " at id: " + id + " (line " + lineNumber + ")");
                            methodCallMap.put(mapperMethod, new HashSet<>());
                        }
                    }
                }
            }
        } catch (IOException | XMLStreamException e) {
            logger.error("Failed to parse XML file: " + path, e);
        }
    }

    private static void parseAndAnalyzeJavaFile(Path path) {
        try (FileInputStream in = new FileInputStream(path.toFile())) {
            CompilationUnit cu = javaParser.parse(in).getResult().orElse(null);
            if (cu != null) {
                cu.accept(new JavaFileVisitor(path.toString()), null);
            }
        } catch (IOException e) {
            logger.error("Failed to parse file: " + path, e);
        }
    }

    private static class JavaFileVisitor extends VoidVisitorAdapter<Void> {
        private final String filePath;

        public JavaFileVisitor(String filePath) {
            this.filePath = filePath;
        }

        @Override
        public void visit(ClassOrInterfaceDeclaration cid, Void arg) {
            if (cid.getAnnotationByName("Controller").isPresent()) {
                cid.getMethods().forEach(method -> method.accept(new ControllerMethodVisitor(filePath), null));
            } else {
                cid.getMethods().forEach(method -> method.accept(new GeneralMethodVisitor(filePath, cid.getNameAsString()), null));
            }
            super.visit(cid, arg);
        }
    }

    private static class ControllerMethodVisitor extends VoidVisitorAdapter<Void> {
        private final String filePath;

        public ControllerMethodVisitor(String filePath) {
            this.filePath = filePath;
        }

        @Override
        public void visit(MethodDeclaration md, Void arg) {
            if (md.getAnnotationByName("RequestMapping").isPresent()) {
                String urlMapping = md.getAnnotationByName("RequestMapping").get().toString();
                md.getBody().ifPresent(body -> body.accept(new MethodCallVisitor(filePath, urlMapping), null));
            }
            super.visit(md, arg);
        }
    }

    private static class GeneralMethodVisitor extends VoidVisitorAdapter<Void> {
        private final String filePath;
        private final String className;

        public GeneralMethodVisitor(String filePath, String className) {
            this.filePath = filePath;
            this.className = className;
        }

        @Override
        public void visit(MethodDeclaration md, Void arg) {
            String methodName = md.getNameAsString();
            String fullMethodName = className + "." + methodName;
            md.getBody().ifPresent(body -> body.accept(new MethodCallVisitor(filePath, fullMethodName), null));
            super.visit(md, arg);
        }
    }

    private static class MethodCallVisitor extends VoidVisitorAdapter<Void> {
        private final String filePath;
        private final String callerMethod;

        public MethodCallVisitor(String filePath, String callerMethod) {
            this.filePath = filePath;
            this.callerMethod = callerMethod;
        }

        @Override
        public void visit(MethodCallExpr mce, Void arg) {
            String methodName = mce.getNameAsString();
            String scope = mce.getScope().map(Object::toString).orElse("");
            String calleeMethod = scope + "." + methodName;

            if (methodCallMap.containsKey(calleeMethod)) {
                methodCallMap.get(calleeMethod).add(callerMethod);
            } else {
                methodCallMap.put(calleeMethod, new HashSet<>(Collections.singletonList(callerMethod)));
            }

            super.visit(mce, arg);
        }
    }
}
