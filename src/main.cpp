#include <iostream>
#include <iomanip>
#include <string>
#include <memory>
#include <mysql_driver.h>
#include <mysql_connection.h>
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/connection.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
#include <openssl/sha.h> // SHA-256
#include <sstream>
#include <mutex>
#include <fstream>
#include <ctime>

std::mutex logMutex;

// 日志记录函数
void logOperation(const std::string &operation, const std::string &details) {
    std::lock_guard<std::mutex> lock(logMutex);
    std::ofstream logFile("operations.log", std::ios::app);
    if (!logFile.is_open()) {
        std::cerr << "无法打开日志文件。\n";
        return;
    }

    std::time_t now = std::time(nullptr);
    char timeStr[20];
    std::strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    logFile << "[" << timeStr << "] " << operation << ": " << details << "\n";
}

// 连接数据库
sql::Connection* connectDatabase() {
    try {
        sql::mysql::MySQL_Driver *driver = sql::mysql::get_mysql_driver_instance();
        sql::Connection *conn = driver->connect("tcp://127.0.0.1:3306", "root", "Zoomhj123!");
        conn->setSchema("test_project");
        std::cout << "数据库连接成功！" << std::endl;
        return conn;
    } catch (sql::SQLException &e) {
        std::cerr << "数据库连接失败: " << e.what() << std::endl;
        return nullptr;
    }
}
std::string hashPassword(const std::string &password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password.c_str(), password.size());
    SHA256_Final(hash, &sha256);

    std::stringstream ss;
    for (unsigned char c : hash) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    return ss.str();
}
bool login(sql::Connection *conn, std::string &currentUser, std::string &role) {
    std::string username, password;
    std::cout << "请输入用户名: ";
    std::cin >> username;
    std::cout << "请输入密码: ";
    std::cin >> password;

    try {
        std::unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement(
            "SELECT role, password_hash FROM users WHERE name = ?"));
        pstmt->setString(1, username);
        std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());

        if (res->next()) {
            std::string storedHash = res->getString("password_hash");
            std::string inputHash = hashPassword(password);

            if (storedHash == inputHash) {
                role = res->getString("role");
                currentUser = username;
                std::cout << "登录成功！欢迎，" << username << "！" << std::endl;
                logOperation("登录", username + " 成功登录系统");
                return true;
            }
        }
        std::cerr << "用户名或密码错误！" << std::endl;
        logOperation("登录失败", username + " 尝试登录失败");
        return false;
    } catch (sql::SQLException &e) {
        std::cerr << "查询错误: " << e.what() << std::endl;
        return false;
    }
}
void updateUser(sql::Connection *conn, const std::string &currentUser, const std::string &role) {
    if (role != "admin" && role != "CEO") {
        std::cerr << "无权限修改用户信息！" << std::endl;
        return;
    }

    std::string targetUser, newEmail;
    std::cout << "请输入要修改的用户名: ";
    std::cin >> targetUser;
    std::cout << "请输入新的邮箱: ";
    std::cin >> newEmail;

    try {
        std::unique_ptr<sql::PreparedStatement> pstmt;

        if (role == "CEO") {
            // CEO 可以修改任意用户信息
            pstmt.reset(conn->prepareStatement(
                "UPDATE users SET email = ? WHERE LOWER(name) = LOWER(?)"));
            pstmt->setString(1, newEmail);
            pstmt->setString(2, targetUser);
        } else { // 部门经理
            // 使用子查询查找当前用户的部门ID，避免直接引用 users 表
            pstmt.reset(conn->prepareStatement(
                "UPDATE users "
                "SET email = ? "
                "WHERE name = ? AND department_id = ("
                "    SELECT dept_id FROM ("
                "        SELECT department_id AS dept_id "
                "        FROM users "
                "        WHERE name = ?"
                "    ) AS temp_table)"
            ));
            pstmt->setString(1, newEmail);
            pstmt->setString(2, targetUser);
            pstmt->setString(3, currentUser);
        }

        // 执行更新操作
        int rows = pstmt->executeUpdate();
        if (rows > 0) {
            std::cout << "用户信息修改成功！" << std::endl;
            logOperation("修改用户信息", currentUser + " 修改了用户: " + targetUser);
        } else {
            std::cerr << "修改失败，检查权限或用户名是否正确！" << std::endl;
        }
    } catch (sql::SQLException &e) {
        std::cerr << "更新错误: " << e.what() << std::endl;
    }
}

int main() {
    sql::Connection *conn = connectDatabase();
    if (!conn) return 1;

    std::string currentUser, role;
    if (!login(conn, currentUser, role)) {
        delete conn;
        return 1;
    }

    int choice;
    do {
        std::cout << "\n请选择操作：\n1. 修改用户信息\n2. 退出\n";
        std::cin >> choice;

        switch (choice) {
        case 1:
            updateUser(conn, currentUser, role);
            break;
        case 2:
            std::cout << "退出系统，再见！" << std::endl;
            logOperation("退出系统", currentUser + " 退出系统");
            break;
        default:
            std::cout << "无效选项，请重试！" << std::endl;
        }
    } while (choice != 2);

    delete conn;
    return 0;
}
