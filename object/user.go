// Copyright 2021 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package object

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/faceId"
	"github.com/casdoor/casdoor/i18n"
	"github.com/casdoor/casdoor/util"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/xorm-io/builder"
	"github.com/xorm-io/core"
	"github.com/xorm-io/xorm"
)

const (
	UserPropertiesWechatUnionId = "wechatUnionId"
	UserPropertiesWechatOpenId  = "wechatOpenId"
	UserPropertiesMergedUsers   = "mergedUsers"
)

const UserEnforcerId = "built-in/user-enforcer-built-in"

const RequiredUpdatePassword = "RequiredUpdatePassword"

var userEnforcer *UserGroupEnforcer

func InitUserManager() {
	enforcer, err := GetInitializedEnforcer(UserEnforcerId)
	if err != nil {
		panic(err)
	}

	userEnforcer = NewUserGroupEnforcer(&casbin.SyncedEnforcer{Enforcer: enforcer.Enforcer})
}

type User struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name        string `xorm:"varchar(255) notnull pk" json:"name"`
	CreatedTime string `xorm:"varchar(100) index" json:"createdTime"`
	UpdatedTime string `xorm:"varchar(100)" json:"updatedTime"`
	DeletedTime string `xorm:"varchar(100)" json:"deletedTime"`

	Id                   string     `xorm:"varchar(100) index" json:"id"`
	ExternalId           string     `xorm:"varchar(100) index" json:"externalId"`
	Type                 string     `xorm:"varchar(100)" json:"type"`
	Password             string     `xorm:"varchar(150)" json:"password"`
	PasswordSalt         string     `xorm:"varchar(100)" json:"passwordSalt"`
	PasswordType         string     `xorm:"varchar(100)" json:"passwordType"`
	DisplayName          string     `xorm:"varchar(100)" json:"displayName"`
	FirstName            string     `xorm:"varchar(100)" json:"firstName"`
	LastName             string     `xorm:"varchar(100)" json:"lastName"`
	Avatar               string     `xorm:"text" json:"avatar"`
	AvatarType           string     `xorm:"varchar(100)" json:"avatarType"`
	PermanentAvatar      string     `xorm:"varchar(500)" json:"permanentAvatar"`
	Email                string     `xorm:"varchar(100) index" json:"email"`
	EmailVerified        bool       `json:"emailVerified"`
	Phone                string     `xorm:"varchar(100) index" json:"phone"`
	CountryCode          string     `xorm:"varchar(6)" json:"countryCode"`
	Region               string     `xorm:"varchar(100)" json:"region"`
	Location             string     `xorm:"varchar(100)" json:"location"`
	Address              []string   `json:"address"`
	Addresses            []*Address `xorm:"addresses blob" json:"addresses"`
	Affiliation          string     `xorm:"varchar(100)" json:"affiliation"`
	Title                string     `xorm:"varchar(100)" json:"title"`
	IdCardType           string     `xorm:"varchar(100)" json:"idCardType"`
	IdCard               string     `xorm:"varchar(100) index" json:"idCard"`
	RealName             string     `xorm:"varchar(100)" json:"realName"`
	IsVerified           bool       `json:"isVerified"`
	Homepage             string     `xorm:"varchar(100)" json:"homepage"`
	Bio                  string     `xorm:"varchar(100)" json:"bio"`
	Tag                  string     `xorm:"varchar(100)" json:"tag"`
	Language             string     `xorm:"varchar(100)" json:"language"`
	Gender               string     `xorm:"varchar(100)" json:"gender"`
	Birthday             string     `xorm:"varchar(100)" json:"birthday"`
	Education            string     `xorm:"varchar(100)" json:"education"`
	Score                int        `json:"score"`
	Karma                int        `json:"karma"`
	Ranking              int        `json:"ranking"`
	Balance              float64    `json:"balance"`
	BalanceCredit        float64    `json:"balanceCredit"`
	Currency             string     `xorm:"varchar(100)" json:"currency"`
	BalanceCurrency      string     `xorm:"varchar(100)" json:"balanceCurrency"`
	IsDefaultAvatar      bool       `json:"isDefaultAvatar"`
	IsOnline             bool       `json:"isOnline"`
	IsAdmin              bool       `json:"isAdmin"`
	IsForbidden          bool       `json:"isForbidden"`
	IsDeleted            bool       `json:"isDeleted"`
	PendingApproval      bool       `json:"pendingApproval"`
	SignupApplication    string     `xorm:"varchar(100)" json:"signupApplication"`
	Hash                 string     `xorm:"varchar(100)" json:"hash"`
	PreHash              string     `xorm:"varchar(100)" json:"preHash"`
	RegisterType         string     `xorm:"varchar(100)" json:"registerType"`
	RegisterSource       string     `xorm:"varchar(100)" json:"registerSource"`
	AccessToken          string     `xorm:"mediumtext" json:"accessToken"`
	OriginalToken        string     `xorm:"mediumtext" json:"originalToken"`
	OriginalRefreshToken string     `xorm:"mediumtext" json:"originalRefreshToken"`

	CreatedIp      string `xorm:"varchar(100)" json:"createdIp"`
	LastSigninTime string `xorm:"varchar(100)" json:"lastSigninTime"`
	LastSigninIp   string `xorm:"varchar(100)" json:"lastSigninIp"`

	GitHub          string `xorm:"github varchar(100)" json:"github"`
	Google          string `xorm:"varchar(100)" json:"google"`
	QQ              string `xorm:"qq varchar(100)" json:"qq"`
	WeChat          string `xorm:"wechat varchar(100)" json:"wechat"`
	Facebook        string `xorm:"facebook varchar(100)" json:"facebook"`
	DingTalk        string `xorm:"dingtalk varchar(100)" json:"dingtalk"`
	Weibo           string `xorm:"weibo varchar(100)" json:"weibo"`
	Gitee           string `xorm:"gitee varchar(100)" json:"gitee"`
	LinkedIn        string `xorm:"linkedin varchar(100)" json:"linkedin"`
	Wecom           string `xorm:"wecom varchar(100)" json:"wecom"`
	Lark            string `xorm:"lark varchar(100)" json:"lark"`
	Gitlab          string `xorm:"gitlab varchar(100)" json:"gitlab"`
	Adfs            string `xorm:"adfs varchar(100)" json:"adfs"`
	Baidu           string `xorm:"baidu varchar(100)" json:"baidu"`
	Alipay          string `xorm:"alipay varchar(100)" json:"alipay"`
	Casdoor         string `xorm:"casdoor varchar(100)" json:"casdoor"`
	Infoflow        string `xorm:"infoflow varchar(100)" json:"infoflow"`
	Apple           string `xorm:"apple varchar(100)" json:"apple"`
	AzureAD         string `xorm:"azuread varchar(100)" json:"azuread"`
	AzureADB2c      string `xorm:"azureadb2c varchar(100)" json:"azureadb2c"`
	Slack           string `xorm:"slack varchar(100)" json:"slack"`
	Steam           string `xorm:"steam varchar(100)" json:"steam"`
	Bilibili        string `xorm:"bilibili varchar(100)" json:"bilibili"`
	Okta            string `xorm:"okta varchar(100)" json:"okta"`
	Douyin          string `xorm:"douyin varchar(100)" json:"douyin"`
	Kwai            string `xorm:"kwai varchar(100)" json:"kwai"`
	Line            string `xorm:"line varchar(100)" json:"line"`
	Amazon          string `xorm:"amazon varchar(100)" json:"amazon"`
	Auth0           string `xorm:"auth0 varchar(100)" json:"auth0"`
	BattleNet       string `xorm:"battlenet varchar(100)" json:"battlenet"`
	Bitbucket       string `xorm:"bitbucket varchar(100)" json:"bitbucket"`
	Box             string `xorm:"box varchar(100)" json:"box"`
	CloudFoundry    string `xorm:"cloudfoundry varchar(100)" json:"cloudfoundry"`
	Dailymotion     string `xorm:"dailymotion varchar(100)" json:"dailymotion"`
	Deezer          string `xorm:"deezer varchar(100)" json:"deezer"`
	DigitalOcean    string `xorm:"digitalocean varchar(100)" json:"digitalocean"`
	Discord         string `xorm:"discord varchar(100)" json:"discord"`
	Dropbox         string `xorm:"dropbox varchar(100)" json:"dropbox"`
	EveOnline       string `xorm:"eveonline varchar(100)" json:"eveonline"`
	Fitbit          string `xorm:"fitbit varchar(100)" json:"fitbit"`
	Gitea           string `xorm:"gitea varchar(100)" json:"gitea"`
	Heroku          string `xorm:"heroku varchar(100)" json:"heroku"`
	InfluxCloud     string `xorm:"influxcloud varchar(100)" json:"influxcloud"`
	Instagram       string `xorm:"instagram varchar(100)" json:"instagram"`
	Intercom        string `xorm:"intercom varchar(100)" json:"intercom"`
	Kakao           string `xorm:"kakao varchar(100)" json:"kakao"`
	Lastfm          string `xorm:"lastfm varchar(100)" json:"lastfm"`
	Mailru          string `xorm:"mailru varchar(100)" json:"mailru"`
	Meetup          string `xorm:"meetup varchar(100)" json:"meetup"`
	MicrosoftOnline string `xorm:"microsoftonline varchar(100)" json:"microsoftonline"`
	Naver           string `xorm:"naver varchar(100)" json:"naver"`
	Nextcloud       string `xorm:"nextcloud varchar(100)" json:"nextcloud"`
	OneDrive        string `xorm:"onedrive varchar(100)" json:"onedrive"`
	Oura            string `xorm:"oura varchar(100)" json:"oura"`
	Patreon         string `xorm:"patreon varchar(100)" json:"patreon"`
	Paypal          string `xorm:"paypal varchar(100)" json:"paypal"`
	SalesForce      string `xorm:"salesforce varchar(100)" json:"salesforce"`
	Shopify         string `xorm:"shopify varchar(100)" json:"shopify"`
	Soundcloud      string `xorm:"soundcloud varchar(100)" json:"soundcloud"`
	Spotify         string `xorm:"spotify varchar(100)" json:"spotify"`
	Strava          string `xorm:"strava varchar(100)" json:"strava"`
	Stripe          string `xorm:"stripe varchar(100)" json:"stripe"`
	Telegram        string `xorm:"telegram varchar(100)" json:"telegram"`
	TikTok          string `xorm:"tiktok varchar(100)" json:"tiktok"`
	Tumblr          string `xorm:"tumblr varchar(100)" json:"tumblr"`
	Twitch          string `xorm:"twitch varchar(100)" json:"twitch"`
	Twitter         string `xorm:"twitter varchar(100)" json:"twitter"`
	Typetalk        string `xorm:"typetalk varchar(100)" json:"typetalk"`
	Uber            string `xorm:"uber varchar(100)" json:"uber"`
	VK              string `xorm:"vk varchar(100)" json:"vk"`
	Wepay           string `xorm:"wepay varchar(100)" json:"wepay"`
	Xero            string `xorm:"xero varchar(100)" json:"xero"`
	Yahoo           string `xorm:"yahoo varchar(100)" json:"yahoo"`
	Yammer          string `xorm:"yammer varchar(100)" json:"yammer"`
	Yandex          string `xorm:"yandex varchar(100)" json:"yandex"`
	Zoom            string `xorm:"zoom varchar(100)" json:"zoom"`
	Oidc            string `xorm:"oidc varchar(100)" json:"oidc"`
	Custom          string `xorm:"custom varchar(100)" json:"custom"`
	Custom2         string `xorm:"custom2 text" json:"custom2"`
	Custom3         string `xorm:"custom3 text" json:"custom3"`
	Custom4         string `xorm:"custom4 text" json:"custom4"`
	Custom5         string `xorm:"custom5 text" json:"custom5"`
	Custom6         string `xorm:"custom6 text" json:"custom6"`
	Custom7         string `xorm:"custom7 text" json:"custom7"`
	Custom8         string `xorm:"custom8 text" json:"custom8"`
	Custom9         string `xorm:"custom9 text" json:"custom9"`
	Custom10        string `xorm:"custom10 text" json:"custom10"`

	WebauthnCredentials []webauthn.Credential `xorm:"webauthnCredentials blob" json:"webauthnCredentials"`
	PreferredMfaType    string                `xorm:"varchar(100)" json:"preferredMfaType"`
	RecoveryCodes       []string              `xorm:"mediumtext" json:"recoveryCodes"`
	TotpSecret          string                `xorm:"varchar(100)" json:"totpSecret"`
	MfaPhoneEnabled     bool                  `json:"mfaPhoneEnabled"`
	MfaEmailEnabled     bool                  `json:"mfaEmailEnabled"`
	MfaRadiusEnabled    bool                  `json:"mfaRadiusEnabled"`
	MfaRadiusUsername   string                `xorm:"varchar(100)" json:"mfaRadiusUsername"`
	MfaRadiusProvider   string                `xorm:"varchar(100)" json:"mfaRadiusProvider"`
	MfaPushEnabled      bool                  `json:"mfaPushEnabled"`
	MfaPushReceiver     string                `xorm:"varchar(100)" json:"mfaPushReceiver"`
	MfaPushProvider     string                `xorm:"varchar(100)" json:"mfaPushProvider"`
	MultiFactorAuths    []*MfaProps           `xorm:"-" json:"multiFactorAuths,omitempty"`
	Invitation          string                `xorm:"varchar(100) index" json:"invitation"`
	InvitationCode      string                `xorm:"varchar(100) index" json:"invitationCode"`
	FaceIds             []*FaceId             `json:"faceIds"`
	Cart                []ProductInfo         `xorm:"mediumtext" json:"cart"`

	Ldap string `xorm:"ldap varchar(100)" json:"ldap"`
	// UidNumber is the POSIX uid published by the built-in LDAP server, 0 when unassigned.
	UidNumber  int               `xorm:"index" json:"uidNumber"`
	Properties map[string]string `json:"properties"`

	ThirdPartyLinks []*ThirdPartyLink `xorm:"-" json:"thirdPartyLinks,omitempty"`

	Roles       []*Role       `json:"roles"`
	Permissions []*Permission `json:"permissions"`
	Groups      []string      `xorm:"mediumtext" json:"groups"`

	LastChangePasswordTime string `xorm:"varchar(100)" json:"lastChangePasswordTime"`
	LastSigninWrongTime    string `xorm:"varchar(100)" json:"lastSigninWrongTime"`
	SigninWrongTimes       int    `json:"signinWrongTimes"`

	ManagedAccounts     []ManagedAccount `xorm:"managedAccounts blob" json:"managedAccounts"`
	MfaAccounts         []MfaAccount     `xorm:"mfaAccounts blob" json:"mfaAccounts"`
	MfaItems            []*MfaItem       `xorm:"varchar(300)" json:"mfaItems"`
	MfaRememberDeadline string           `xorm:"varchar(100)" json:"mfaRememberDeadline"`
	NeedUpdatePassword  bool             `json:"needUpdatePassword"`
	IpWhitelist         string           `xorm:"varchar(200)" json:"ipWhitelist"`
	ApplicationScopes   []ConsentRecord  `xorm:"mediumtext" json:"applicationScopes"`
}

type Userinfo struct {
	Sub           string       `json:"sub"`
	Iss           string       `json:"iss"`
	Aud           string       `json:"aud"`
	Name          string       `json:"preferred_username,omitempty"`
	DisplayName   string       `json:"name,omitempty"`
	Email         string       `json:"email,omitempty"`
	EmailVerified bool         `json:"email_verified,omitempty"`
	Avatar        string       `json:"picture,omitempty"`
	Address       *OIDCAddress `json:"address,omitempty"`
	Phone         string       `json:"phone,omitempty"`
	PhoneNumber   string       `json:"phone_number,omitempty"`
	RealName      string       `json:"real_name,omitempty"`
	IsVerified    bool         `json:"is_verified,omitempty"`
	Groups        []string     `json:"groups,omitempty"`
	Roles         []string     `json:"roles,omitempty"`
	Permissions   []string     `json:"permissions,omitempty"`

	CustomClaims map[string]interface{} `json:"-"`
}

func (u Userinfo) MarshalJSON() ([]byte, error) {
	type userinfo Userinfo
	data, err := json.Marshal(userinfo(u))
	if err != nil || len(u.CustomClaims) == 0 {
		return data, err
	}

	res := map[string]interface{}{}
	err = json.Unmarshal(data, &res)
	if err != nil {
		return nil, err
	}
	for name, value := range u.CustomClaims {
		if _, ok := res[name]; !ok {
			res[name] = value
		}
	}
	return json.Marshal(res)
}

type ManagedAccount struct {
	Application string `xorm:"varchar(100)" json:"application"`
	Username    string `xorm:"varchar(100)" json:"username"`
	Password    string `xorm:"varchar(100)" json:"password"`
	SigninUrl   string `xorm:"varchar(200)" json:"signinUrl"`
}

type MfaAccount struct {
	AccountName string `xorm:"varchar(100)" json:"accountName"`
	Issuer      string `xorm:"varchar(100)" json:"issuer"`
	SecretKey   string `xorm:"varchar(100)" json:"secretKey"`
	Origin      string `xorm:"varchar(100)" json:"origin"`
}

type Address struct {
	Tag     string `xorm:"varchar(100)" json:"tag"`
	Line1   string `xorm:"varchar(100)" json:"line1"`
	Line2   string `xorm:"varchar(100)" json:"line2"`
	City    string `xorm:"varchar(100)" json:"city"`
	State   string `xorm:"varchar(100)" json:"state"`
	ZipCode string `xorm:"varchar(100)" json:"zipCode"`
	Region  string `xorm:"varchar(100)" json:"region"`
}

type FaceId struct {
	Name       string    `xorm:"varchar(100) notnull pk" json:"name"`
	FaceIdData []float64 `json:"faceIdData"`
	ImageUrl   string    `json:"imageUrl"`
}

func GetUserFieldStringValue(user *User, fieldName string) (bool, string, error) {
	val := reflect.ValueOf(*user)
	fieldValue := val.FieldByName(fieldName)

	if !fieldValue.IsValid() {
		return false, "", nil
	}

	if fieldValue.Kind() == reflect.String {
		return true, fieldValue.String(), nil
	}

	marshalValue, err := json.Marshal(fieldValue.Interface())
	if err != nil {
		return false, "", err
	}

	return true, string(marshalValue), nil
}

func GetGlobalUserCount(field, value string) (int64, error) {
	session := GetSession("", -1, -1, field, value, "", "")
	return session.Count(&User{})
}

func GetGlobalUsers() ([]*User, error) {
	users := []*User{}
	err := ormer.Engine.Desc("created_time").Find(&users)
	if err != nil {
		return nil, err
	}

	return users, nil
}

func GetGlobalUsersWithFilter(cond builder.Cond) ([]*User, error) {
	users := []*User{}
	session := ormer.Engine.Desc("created_time")
	if cond != nil {
		session = session.Where(cond)
	}
	err := session.Find(&users)
	if err != nil {
		return nil, err
	}

	return users, nil
}

func GetPaginationGlobalUsers(offset, limit int, field, value, sortField, sortOrder string) ([]*User, error) {
	users := []*User{}
	session := GetSessionForUser("", offset, limit, field, value, sortField, sortOrder)
	err := session.Find(&users)
	if err != nil {
		return nil, err
	}

	return users, nil
}

func GetUserCount(owner, field, value string, groupName string) (int64, error) {
	session := GetSession(owner, -1, -1, field, value, "", "")

	if groupName != "" {
		return GetGroupUserCount(util.GetId(owner, groupName), field, value)
	}

	return session.Count(&User{})
}

func GetUserCountWithFilter(owner string, cond builder.Cond) (int64, error) {
	session := GetSession(owner, -1, -1, "", "", "", "")
	return session.And(cond).Count(&User{})
}

func GetOnlineUserCount(owner string, isOnline int) (int64, error) {
	return ormer.Engine.Where("is_online = ?", isOnline).Count(&User{Owner: owner})
}

func GetUsers(owner string) ([]*User, error) {
	users := []*User{}
	err := ormer.Engine.Desc("created_time").Find(&users, &User{Owner: owner})
	if err != nil {
		return nil, err
	}

	return users, nil
}

func GetUsersWithFilter(owner string, cond builder.Cond) ([]*User, error) {
	users := []*User{}
	session := ormer.Engine.Desc("created_time")
	if cond != nil {
		session = session.Where(cond)
	}
	err := session.Find(&users, &User{Owner: owner})
	if err != nil {
		return nil, err
	}

	return users, nil
}

func GetUsersByTagWithFilter(owner string, tag string, cond builder.Cond) ([]*User, error) {
	users := []*User{}
	session := ormer.Engine.Desc("created_time")
	if cond != nil {
		session = session.Where(cond)
	}
	err := session.Find(&users, &User{Owner: owner, Tag: tag})
	if err != nil {
		return nil, err
	}

	return users, nil
}

func GetSortedUsers(owner string, sorter string, limit int) ([]*User, error) {
	users := []*User{}
	if !util.FilterSQLIdentifier(sorter) {
		return nil, fmt.Errorf("object.GetSortedUsers() error: invalid sorter field: %s", sorter)
	}
	err := ormer.Engine.Desc(sorter).Limit(limit, 0).Find(&users, &User{Owner: owner})
	if err != nil {
		return nil, err
	}

	return users, nil
}

func GetPaginationUsers(owner string, offset, limit int, field, value, sortField, sortOrder string, groupName string) ([]*User, error) {
	users := []*User{}

	if groupName != "" {
		return GetPaginationGroupUsers(util.GetId(owner, groupName), offset, limit, field, value, sortField, sortOrder)
	}

	session := GetSessionForUser(owner, offset, limit, field, value, sortField, sortOrder)
	err := session.Find(&users)
	if err != nil {
		return nil, err
	}
	return users, nil
}

func GetPaginationUsersWithFilter(owner string, offset, limit int, cond builder.Cond) ([]*User, error) {
	users := []*User{}
	session := GetSession(owner, offset, limit, "", "", "", "")
	err := session.And(cond).Find(&users)
	if err != nil {
		return nil, err
	}
	return users, nil
}

func getUser(owner string, name string) (*User, error) {
	if owner == "" || name == "" {
		return nil, nil
	}

	user := User{Owner: owner, Name: name}
	existed, err := ormer.Engine.Get(&user)
	if err != nil {
		return nil, err
	}

	if existed {
		return &user, nil
	} else {
		return nil, nil
	}
}

func getUserById(owner string, id string) (*User, error) {
	if owner == "" || id == "" {
		return nil, nil
	}

	user := User{Owner: owner, Id: id}
	existed, err := ormer.Engine.Get(&user)
	if err != nil {
		return nil, err
	}

	if existed {
		return &user, nil
	} else {
		return nil, nil
	}
}

func getUserByWechatId(owner string, wechatOpenId string, wechatUnionId string) (*User, error) {
	if wechatUnionId == "" {
		wechatUnionId = wechatOpenId
	}
	user := &User{}
	existed, err := ormer.Engine.Where("owner = ?", owner).Where("wechat = ? OR wechat = ?", wechatOpenId, wechatUnionId).Get(user)
	if err != nil {
		return nil, err
	}

	if existed {
		return user, nil
	} else {
		return nil, nil
	}
}

func GetUserByEmail(owner string, email string) (*User, error) {
	if owner == "" || email == "" {
		return nil, nil
	}

	user := User{Owner: owner, Email: email}
	existed, err := ormer.Engine.Get(&user)
	if err != nil {
		return nil, err
	}

	if existed {
		return &user, nil
	} else {
		return nil, nil
	}
}

func GetUserByWebauthID(webauthId string) (*User, error) {
	user := User{}
	existed := false
	var err error

	if ormer.driverName == "postgres" {
		existed, err = ormer.Engine.Where(builder.Like{"\"webauthnCredentials\"", webauthId}).Get(&user)
	} else if ormer.driverName == "mssql" {
		existed, err = ormer.Engine.Where("CAST(webauthnCredentials AS VARCHAR(MAX)) like ?", "%"+webauthId+"%").Get(&user)
	} else if ormer.driverName == "sqlite" {
		existed, err = ormer.Engine.Where("CAST(webauthnCredentials AS text) like ?", "%"+webauthId+"%").Get(&user)
	} else {
		existed, err = ormer.Engine.Where("webauthnCredentials like ?", "%"+webauthId+"%").Get(&user)
	}
	if err != nil {
		return nil, err
	}

	if !existed {
		return nil, fmt.Errorf("user not exist")
	}

	return &user, err
}

func GetUserByEmailOnly(email string) (*User, error) {
	if email == "" {
		return nil, nil
	}

	user := User{Email: email}
	existed, err := ormer.Engine.Get(&user)
	if err != nil {
		return nil, err
	}

	if existed {
		return &user, nil
	} else {
		return nil, nil
	}
}

func GetUserByPhone(owner string, phone string) (*User, error) {
	if owner == "" || phone == "" {
		return nil, nil
	}

	nationalPhone, regionCode := util.ParseE164Phone(phone)

	user := User{Owner: owner, Phone: nationalPhone, CountryCode: regionCode}
	existed, err := ormer.Engine.Get(&user)
	if err != nil {
		return nil, err
	}

	if existed {
		return &user, nil
	}

	if regionCode == "" {
		return getUserByNationalPhone(owner, phone)
	}
	return nil, nil
}

// GetUserByPhoneWithCountryCode looks up the user of a phone number typed with the chosen country code,
// a national number like "0796488996" is normalized the same way as the one stored at signup
func GetUserByPhoneWithCountryCode(owner string, phone string, countryCode string) (*User, error) {
	if countryCode != "" && !strings.HasPrefix(phone, "+") {
		if e164, ok := util.GetE164Number(phone, countryCode); ok {
			user, err := GetUserByPhone(owner, e164)
			if user != nil || err != nil {
				return user, err
			}
		}
	}

	return GetUserByPhone(owner, phone)
}

func GetUserByPhoneOnly(phone string) (*User, error) {
	if phone == "" {
		return nil, nil
	}

	nationalPhone, regionCode := util.ParseE164Phone(phone)

	user := User{Phone: nationalPhone, CountryCode: regionCode}
	existed, err := ormer.Engine.Get(&user)
	if err != nil {
		return nil, err
	}

	if existed {
		return &user, nil
	} else {
		return nil, nil
	}
}

func GetUserByUserId(owner string, userId string) (*User, error) {
	if owner == "" || userId == "" {
		return nil, nil
	}

	user := User{Owner: owner, Id: userId}
	existed, err := ormer.Engine.Get(&user)
	if err != nil {
		return nil, err
	}

	if existed {
		return &user, nil
	} else {
		return nil, nil
	}
}

func GetUserByUserIdOnly(userId string) (*User, error) {
	if userId == "" {
		return nil, nil
	}

	user := User{Id: userId}
	existed, err := ormer.Engine.Get(&user)
	if err != nil {
		return nil, err
	}

	if existed {
		return &user, nil
	} else {
		return nil, nil
	}
}

func GetUserByInvitationCode(owner string, invitationCode string) (*User, error) {
	if owner == "" || invitationCode == "" {
		return nil, nil
	}

	user := User{Owner: owner, InvitationCode: invitationCode}
	existed, err := ormer.Engine.Get(&user)
	if err != nil {
		return nil, err
	}

	if existed {
		return &user, nil
	} else {
		return nil, nil
	}
}

func GetUser(id string) (*User, error) {
	owner, name, err := util.GetOwnerAndNameFromIdWithError(id)
	if err != nil {
		return nil, err
	}
	user, err := getUser(owner, name)
	if err != nil {
		return nil, err
	}
	if user != nil {
		err = user.PopulateThirdPartyLinks()
		if err != nil {
			return nil, err
		}
	}
	return user, nil
}

func GetUserNoCheck(id string) (*User, error) {
	owner, name := util.GetOwnerAndNameFromIdNoCheck(id)
	return getUser(owner, name)
}

func GetMaskedUser(user *User, isAdminOrSelf bool, errs ...error) (*User, error) {
	if len(errs) > 0 && errs[0] != nil {
		return nil, errs[0]
	}

	if user == nil {
		return nil, nil
	}

	if user.Password != "" {
		user.Password = "***"
	}

	if !isAdminOrSelf {
		if user.OriginalToken != "" {
			user.OriginalToken = "***"
		}
		if user.OriginalRefreshToken != "" {
			user.OriginalRefreshToken = "***"
		}
		user.FaceIds = nil
		// Mask per-provider OAuth tokens in Properties
		if user.Properties != nil {
			for key := range user.Properties {
				// More specific pattern matching to avoid masking unrelated properties
				if strings.HasPrefix(key, "oauth_") && (strings.HasSuffix(key, "_accessToken") || strings.HasSuffix(key, "_refreshToken")) {
					user.Properties[key] = "***"
				}
			}
		}
		user.PasswordSalt = ""
		user.PasswordType = ""
	}

	// the passwords of the managed accounts are only handed out by form autofill, not even to the admins
	for i := range user.ManagedAccounts {
		if user.ManagedAccounts[i].Password != "" {
			user.ManagedAccounts[i].Password = "***"
		}
	}

	// the authenticator app syncs the secrets of the user's own MFA accounts
	if !isAdminOrSelf {
		for i := range user.MfaAccounts {
			if user.MfaAccounts[i].SecretKey != "" {
				user.MfaAccounts[i].SecretKey = "***"
			}
		}
	}

	if user.TotpSecret != "" {
		user.TotpSecret = ""
	}
	if user.RecoveryCodes != nil {
		user.RecoveryCodes = nil
	}

	return user, nil
}

func getOAuthDisplayProperties(properties map[string]string) map[string]string {
	res := map[string]string{}
	for key, value := range properties {
		if !strings.HasPrefix(key, "oauth_") {
			continue
		}
		for _, suffix := range []string{"_id", "_username", "_displayName", "_email", "_avatarUrl"} {
			if strings.HasSuffix(key, suffix) {
				res[key] = value
				break
			}
		}
	}
	return res
}

func GetFilteredUser(user *User, isAdmin bool, isAdminOrSelf bool, accountItems []*AccountItem) (*User, error) {
	if accountItems == nil || len(accountItems) == 0 {
		return user, nil
	}

	userFieldMap := map[string]int{}

	reflectedUserField := reflect.TypeOf(User{})
	for i := 0; i < reflectedUserField.NumField(); i++ {
		userFieldMap[strings.ToLower(reflectedUserField.Field(i).Name)] = i
	}

	reflectedUser := reflect.ValueOf(user).Elem()

	for _, accountItem := range accountItems {
		if accountItem.ViewRule == "Public" {
			continue
		} else if accountItem.ViewRule == "Self" && isAdminOrSelf {
			continue
		} else if accountItem.ViewRule == "Admin" && isAdmin {
			continue
		}

		lowerCaseAccountItemName := strings.ToLower(accountItem.Name)
		lowerCaseAccountItemName = strings.ReplaceAll(lowerCaseAccountItemName, " ", "")

		switch accountItem.Name {
		case "Multi-factor authentication":
			lowerCaseAccountItemName = strings.ToLower("PreferredMfaType")
		case "User type":
			lowerCaseAccountItemName = "type"
		case "Country/Region":
			lowerCaseAccountItemName = "region"
		case "ID card info":
			{
				infoKeys := []string{"idCardWithPerson", "idCardFront", "idCardWithPerson"}
				for _, infoKey := range infoKeys {
					if _, ok := user.Properties[infoKey]; ok {
						user.Properties[infoKey] = ""
					}
				}
				continue
			}
		case "Properties":
			if isAdminOrSelf {
				user.Properties = getOAuthDisplayProperties(user.Properties)
				continue
			}
		}

		fieldIdx, ok := userFieldMap[lowerCaseAccountItemName]
		if !ok {
			continue
		}

		reflectedUser.Field(fieldIdx).SetZero()
	}

	return user, nil
}

func GetMaskedUsers(users []*User, errs ...error) ([]*User, error) {
	if len(errs) > 0 && errs[0] != nil {
		return nil, errs[0]
	}

	var err error
	for _, user := range users {
		user, err = GetMaskedUser(user, false)
		if err != nil {
			return nil, err
		}
	}
	return users, nil
}

func getLastUser(owner string) (*User, error) {
	user := User{Owner: owner}
	existed, err := ormer.Engine.Desc("created_time", "id").Get(&user)
	if err != nil {
		return nil, err
	}

	if existed {
		return &user, nil
	}

	return nil, nil
}

var userSelfColumns = []string{
	"owner", "display_name", "avatar", "first_name", "last_name",
	"location", "address", "addresses", "country_code", "region", "language", "affiliation", "title", "id_card_type", "id_card", "homepage", "bio", "tag", "language", "gender", "birthday", "education", "score", "karma", "ranking", "signup_application", "register_type", "register_source",
	"hash", "is_default_avatar", "properties", "webauthnCredentials", "mfa_items", "last_change_password_time", "managedAccounts", "face_ids", "mfaAccounts",
	"signin_wrong_times", "last_signin_wrong_time", "groups", "mfa_phone_enabled", "mfa_email_enabled",
	"type", "need_update_password", "ip_whitelist", "mfa_remember_deadline",
	"cart", "application_scopes",
}

// userProviderColumns hold the IDs the sign-in by a provider looks the user up with, only the
// link and unlink flows or an admin may set them, a user choosing their own would take over
// the sign-in of whoever owns that provider account
var userProviderColumns = []string{
	"github", "google", "qq", "wechat", "facebook", "dingtalk", "weibo", "gitee", "linkedin", "wecom", "lark", "gitlab", "adfs",
	"baidu", "alipay", "casdoor", "infoflow", "apple", "azuread", "azureadb2c", "slack", "steam", "bilibili", "okta", "douyin", "kwai", "line", "amazon",
	"auth0", "battlenet", "bitbucket", "box", "cloudfoundry", "dailymotion", "deezer", "digitalocean", "discord", "dropbox",
	"eveonline", "fitbit", "gitea", "heroku", "influxcloud", "instagram", "intercom", "kakao", "lastfm", "mailru", "meetup",
	"microsoftonline", "naver", "nextcloud", "onedrive", "oura", "patreon", "paypal", "salesforce", "shopify", "soundcloud",
	"spotify", "strava", "stripe", "telegram", "tiktok", "tumblr", "twitch", "twitter", "typetalk", "uber", "vk", "wepay", "xero", "yahoo",
	"yammer", "yandex", "zoom", "oidc", "custom",
}

func GetDefaultUserUpdateColumns(isAdmin bool) []string {
	columns := append([]string{}, userSelfColumns...)
	if isAdmin {
		columns = append(columns, "name", "id", "email", "phone", "country_code", "type", "balance", "balance_credit", "balance_currency", "mfa_items", "register_type", "register_source",
			"is_admin", "is_forbidden", "is_deleted", "uid_number", "email_verified", "is_verified")
		columns = append(columns, userProviderColumns...)
	}
	return columns
}

func FilterUserSelfColumns(columns []string) []string {
	res := []string{}
	for _, column := range columns {
		if util.InSlice(userSelfColumns, column) {
			res = append(res, column)
		}
	}
	return res
}

func UpdateUser(id string, user *User, columns []string, isAdmin bool) (bool, error) {
	var err error
	owner, name := util.GetOwnerAndNameFromIdNoCheck(id)
	oldUser, err := getUser(owner, name)
	if err != nil {
		return false, err
	}
	if oldUser == nil {
		return false, fmt.Errorf("the user: %s is not found", id)
	}
	if user.Owner != owner {
		return false, fmt.Errorf("moving a user between organizations is not supported: %s -> %s", owner, user.Owner)
	}

	// Auto-upgrade guest users when they update their username or password
	if oldUser.Tag == "guest-user" {
		// Check if username is being changed from the generated guest username
		usernameChanged := oldUser.Name != user.Name && !strings.HasPrefix(user.Name, "guest_")
		// Check if password is being updated (not the placeholder ***)
		passwordChanged := user.Password != "***" && user.Password != "" && user.Password != oldUser.Password

		if usernameChanged || passwordChanged {
			// Upgrade to normal user
			user.Tag = "normal-user"
			// Ensure tag is included in the update columns
			if !util.InSlice(columns, "tag") && len(columns) > 0 {
				columns = append(columns, "tag")
			}
		}
	}

	if user.Password == "***" {
		user.Password = oldUser.Password
	}

	keepMaskedAccountSecrets(user, oldUser)

	if user.FaceIds == nil {
		user.FaceIds = oldUser.FaceIds
	}

	// only a merge lists the accounts merged into a user, the applications hand their data over by it
	if !isAdmin {
		setUserProperty(user, UserPropertiesMergedUsers, getUserProperty(oldUser, UserPropertiesMergedUsers))
	}

	if user.Id != oldUser.Id && user.Id == "" {
		user.Id = oldUser.Id
	}

	if user.Avatar != oldUser.Avatar && user.Avatar != "" && user.PermanentAvatar != "*" {
		user.PermanentAvatar, err = getPermanentAvatarUrl(user.Owner, user.Name, user.Avatar, false)
		if err != nil {
			return false, err
		}
	}

	if len(columns) == 0 {
		columns = GetDefaultUserUpdateColumns(isAdmin)
	}
	rename := name != user.Name && util.InSlice(columns, "name")
	if name != user.Name && !rename {
		user.Name = name
	}

	// turning off "Is forbidden" approves a user who signed up through an application that needs approval
	if oldUser.PendingApproval && util.InSlice(columns, "is_forbidden") {
		user.PendingApproval = user.IsForbidden
		columns = append(columns, "pending_approval")
	} else {
		user.PendingApproval = oldUser.PendingApproval
	}

	columns = append(columns, "updated_time")
	user.UpdatedTime = util.GetCurrentTime()

	if len(user.DeletedTime) > 0 {
		columns = append(columns, "deleted_time")
	}

	var affected int64
	if rename || util.InSlice(columns, "groups") {
		affected, err = updateUserGroupsWithGovernance(id, user, columns)
	} else {
		affected, err = updateUser(id, user, columns)
	}
	var publicationErr error
	if err != nil {
		if affected == 0 {
			return false, err
		}
		publicationErr = err
	}

	if affected != 0 {
		triggerUserForbiddenWebhook(oldUser, user, columns)
		if isProvisionedUserUpdate(columns) {
			provisionUser(oldUser)
		}
	}

	if affected != 0 && isUserAccessRevoked(oldUser, user, columns) {
		// The tokens and sessions are keyed by the old user name, it may have just been renamed
		err = TerminateUserAccess(oldUser)
		if err != nil {
			terminationErr := fmt.Errorf("the user: %s is updated, but terminating its access failed: %w", id, err)
			if publicationErr != nil {
				return true, errors.Join(publicationErr, terminationErr)
			}
			return true, terminationErr
		}
	}
	if publicationErr != nil {
		return true, fmt.Errorf("the user: %s is updated, but publishing its committed group policy failed: %w", id, publicationErr)
	}

	return affected != 0, nil
}

func updateUserGroupsWithGovernance(id string, user *User, columns []string) (int64, error) {
	owner, name := util.GetOwnerAndNameFromIdNoCheck(id)
	if user.Owner != owner {
		return 0, fmt.Errorf("moving a user between organizations is not supported: %s -> %s", owner, user.Owner)
	}
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err := session.Begin(); err != nil {
		return 0, err
	}
	rollback := func(err error) (int64, error) {
		_ = session.Rollback()
		return 0, err
	}
	if err := lockGovernanceScopes(session, owner, user.Owner); err != nil {
		return rollback(err)
	}
	stored := &User{Owner: owner, Name: name}
	existed, err := session.ForUpdate().Get(stored)
	if err != nil {
		return rollback(err)
	}
	if !existed {
		return rollback(fmt.Errorf("the user: %s is not found", id))
	}
	renamed := name != user.Name
	if renamed {
		if err = moveUserIdentityReferencesInSession(session, stored, user.Name); err != nil {
			return rollback(err)
		}
	}
	if !util.InSlice(columns, "groups") {
		user.Groups = append([]string{}, stored.Groups...)
	}
	if err = CheckUserSodInSession(session, stored, user, ""); err != nil {
		return rollback(err)
	}
	if err = user.UpdateUserHash(); err != nil {
		return rollback(err)
	}
	if !util.InSlice(columns, "hash") {
		columns = append(columns, "hash")
	}
	affected, err := session.ID(core.PK{owner, name}).Cols(columns...).Update(user)
	if err != nil {
		return rollback(err)
	}
	if renamed {
		if err = userEnforcer.deleteGroupsForUserInSession(session, stored.GetId()); err != nil {
			return rollback(err)
		}
	}
	if err = userEnforcer.replaceGroupsForUserInSession(session, user.GetId(), user.Groups); err != nil {
		return rollback(err)
	}
	if err = session.Commit(); err != nil {
		return rollback(err)
	}
	if err = userEnforcer.publishCommittedGroups(); err != nil {
		return affected, err
	}
	return affected, nil
}

func updateUser(id string, user *User, columns []string) (int64, error) {
	owner, name := util.GetOwnerAndNameFromIdNoCheck(id)
	err := user.UpdateUserHash()
	if err != nil {
		return 0, err
	}

	// Ensure hash column is included in updates when columns are specified
	if len(columns) > 0 && !util.InSlice(columns, "hash") {
		columns = append(columns, "hash")
	}

	affected, err := ormer.Engine.ID(core.PK{owner, name}).Cols(columns...).Update(user)
	if err != nil {
		return 0, err
	}
	return affected, nil
}

func UpdateUserForAllFields(id string, user *User) (bool, error) {
	var err error
	owner, name, err := util.GetOwnerAndNameFromIdWithError(id)
	if err != nil {
		return false, err
	}
	oldUser, err := getUser(owner, name)
	if err != nil {
		return false, err
	}

	if oldUser == nil {
		return false, fmt.Errorf("the user: %s is not found", id)
	}
	if user.Owner != owner {
		return false, fmt.Errorf("moving a user between organizations is not supported: %s -> %s", owner, user.Owner)
	}

	err = user.UpdateUserHash()
	if err != nil {
		return false, err
	}

	if user.Avatar != oldUser.Avatar && user.Avatar != "" {
		user.PermanentAvatar, err = getPermanentAvatarUrl(user.Owner, user.Name, user.Avatar, false)
		if err != nil {
			return false, err
		}
	}

	user.UpdatedTime = util.GetCurrentTime()

	// AllCols always writes groups, even when this caller's earlier snapshot
	// happens to match. Re-read and validate under the organization lock so a
	// concurrent membership change cannot be restored from stale profile data.
	affected, err := updateUserAllFieldsGroupsWithGovernance(id, user)
	var publicationErr error
	if err != nil {
		if affected == 0 {
			return false, err
		}
		publicationErr = err
	}

	if affected != 0 {
		triggerUserForbiddenWebhook(oldUser, user, nil)
		provisionUser(oldUser)
	}

	if affected != 0 && isUserAccessRevoked(oldUser, user, nil) {
		err = TerminateUserAccess(oldUser)
		if err != nil {
			terminationErr := fmt.Errorf("the user: %s is updated, but terminating its access failed: %w", id, err)
			if publicationErr != nil {
				return true, errors.Join(publicationErr, terminationErr)
			}
			return true, terminationErr
		}
	}
	if publicationErr != nil {
		return true, fmt.Errorf("the user: %s is updated, but publishing its committed group policy failed: %w", id, publicationErr)
	}

	return affected != 0, nil
}

func updateUserAllFieldsGroupsWithGovernance(id string, user *User) (int64, error) {
	owner, name := util.GetOwnerAndNameFromIdNoCheck(id)
	if user.Owner != owner {
		return 0, fmt.Errorf("moving a user between organizations is not supported: %s -> %s", owner, user.Owner)
	}
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err := session.Begin(); err != nil {
		return 0, err
	}
	rollback := func(err error) (int64, error) {
		_ = session.Rollback()
		return 0, err
	}
	if err := lockGovernanceScopes(session, owner, user.Owner); err != nil {
		return rollback(err)
	}
	stored := &User{Owner: owner, Name: name}
	existed, err := session.ForUpdate().Get(stored)
	if err != nil {
		return rollback(err)
	}
	if !existed {
		return rollback(fmt.Errorf("the user: %s is not found", id))
	}
	renamed := name != user.Name
	if renamed {
		if err = moveUserIdentityReferencesInSession(session, stored, user.Name); err != nil {
			return rollback(err)
		}
	}
	if err = CheckUserSodInSession(session, stored, user, ""); err != nil {
		return rollback(err)
	}
	affected, err := session.ID(core.PK{owner, name}).AllCols().Update(user)
	if err != nil {
		return rollback(err)
	}
	if renamed {
		if err = userEnforcer.deleteGroupsForUserInSession(session, stored.GetId()); err != nil {
			return rollback(err)
		}
	}
	if err = userEnforcer.replaceGroupsForUserInSession(session, user.GetId(), user.Groups); err != nil {
		return rollback(err)
	}
	if err = session.Commit(); err != nil {
		return rollback(err)
	}
	if err = userEnforcer.publishCommittedGroups(); err != nil {
		return affected, err
	}
	return affected, nil
}

func AddUser(user *User, lang string) (bool, error) {
	if user.Id == "" {
		application, err := GetApplicationByUser(user)
		if err != nil {
			return false, err
		}

		id, err := GenerateIdForNewUser(application)
		if err != nil {
			return false, err
		}

		user.Id = id
	}

	if user.Owner == "" || user.Name == "" {
		return false, errors.New(i18n.Translate(lang, "user:the user's owner and name should not be empty"))
	}

	user.Groups = getOrganizationGroups(user.Owner, user.Groups)

	if CheckUsernameWithEmail(user.Name, lang) != "" {
		user.Name = util.GetRandomName()
	}

	organization, err := GetOrganizationByUser(user)
	if err != nil {
		return false, err
	}
	if organization == nil {
		return false, fmt.Errorf(i18n.Translate(lang, "auth:the organization: %s is not found"), user.Owner)
	}

	if user.Owner != "built-in" {
		applicationCount, err := GetOrganizationApplicationCount(organization.Owner, organization.Name, "", "")
		if err != nil {
			return false, err
		}
		if applicationCount == 0 {
			return false, fmt.Errorf(i18n.Translate(lang, "general:The organization: %s should have one application at least"), organization.Name)
		}
	}

	if organization.Name == "built-in" && !organization.HasPrivilegeConsent && user.Name != "admin" {
		return false, errors.New(i18n.Translate(lang, "organization:adding a new user to the 'built-in' organization is currently disabled. Please note: all users in the 'built-in' organization are global administrators in Casdoor. Refer to the docs: https://casdoor.org/docs/basic/core-concepts#how-does-casdoor-manage-itself. If you still wish to create a user for the 'built-in' organization, go to the organization's settings page and enable the 'Has privilege consent' option."))
	}

	if user.BalanceCurrency == "" {
		if organization.BalanceCurrency != "" {
			user.BalanceCurrency = organization.BalanceCurrency
		} else {
			user.BalanceCurrency = "USD"
		}
	}

	if user.Avatar == "" {
		user.Avatar = organization.DefaultAvatar
	}

	if organization.DefaultPassword != "" && user.Password == "123" {
		user.Password = organization.DefaultPassword
	}

	if user.PasswordType == "" || user.PasswordType == "plain" {
		user.UpdateUserPassword(organization)
	}

	if user.CreatedTime == "" {
		user.CreatedTime = util.GetCurrentTime()
	}

	if user.UpdatedTime == "" {
		user.UpdatedTime = user.CreatedTime
	}

	err = user.UpdateUserHash()
	if err != nil {
		return false, err
	}

	user.PreHash = user.Hash

	updated, err := user.refreshAvatar()
	if err != nil {
		return false, err
	}

	if updated && user.PermanentAvatar != "*" {
		user.PermanentAvatar, err = getPermanentAvatarUrl(user.Owner, user.Name, user.Avatar, false)
		if err != nil {
			return false, err
		}
	}

	rankingItem := GetAccountItemByName("Ranking", organization)
	if rankingItem != nil {
		count, err := GetUserCount(user.Owner, "", "", "")
		if err != nil {
			return false, err
		}
		user.Ranking = int(count + 1)
	}

	isUsernameLowered := conf.GetConfigBool("isUsernameLowered")
	if isUsernameLowered {
		user.Name = strings.ToLower(user.Name)
	}
	if err = user.UpdateUserHash(); err != nil {
		return false, err
	}
	user.PreHash = user.Hash

	session := ormer.Engine.NewSession()
	defer session.Close()
	if err = session.Begin(); err != nil {
		return false, err
	}
	rollback := func(err error) (bool, error) {
		_ = session.Rollback()
		return false, err
	}
	if err = lockGovernanceScope(session, user.Owner); err != nil {
		return rollback(err)
	}
	if dependency, err := getUserIdentityDependencyInSession(session, user, false); err != nil {
		return rollback(err)
	} else if dependency != "" {
		return rollback(fmt.Errorf("the user cannot be added while an existing %s depends on the same identity: %s", dependency, user.GetId()))
	}
	if err = CheckUserSodInSession(session, nil, user, lang); err != nil {
		return rollback(err)
	}
	affected, err := session.Insert(user)
	if err != nil {
		return rollback(err)
	}
	groupsStaged, err := stageNewUserGroups(session, user)
	if err != nil {
		return rollback(err)
	}
	if err = session.Commit(); err != nil {
		return rollback(err)
	}
	if groupsStaged {
		if err = userEnforcer.publishCommittedGroups(); err != nil {
			return false, err
		}
	}

	if affected != 0 {
		provisionUser(user)
	}
	return affected != 0, nil
}

func AddUsers(users []*User) (bool, error) {
	if len(users) == 0 {
		return false, fmt.Errorf("no users are provided")
	}

	isUsernameLowered := conf.GetConfigBool("isUsernameLowered")

	// organization := GetOrganizationByUser(users[0])
	for _, user := range users {
		// this function is only used for syncer or batch upload, so no need to encrypt the password
		// user.UpdateUserPassword(organization)

		if user.CreatedTime == "" {
			user.CreatedTime = util.GetCurrentTime()
		}

		if user.UpdatedTime == "" {
			user.UpdatedTime = user.CreatedTime
		}

		err := user.UpdateUserHash()
		if err != nil {
			return false, err
		}

		user.PreHash = user.Hash

		user.PermanentAvatar, err = getPermanentAvatarUrl(user.Owner, user.Name, user.Avatar, true)
		if err != nil {
			return false, err
		}

		user.Name = strings.TrimSpace(user.Name)
		if isUsernameLowered {
			user.Name = strings.ToLower(user.Name)
		}
		if err = user.UpdateUserHash(); err != nil {
			return false, err
		}
		user.PreHash = user.Hash
	}

	session := ormer.Engine.NewSession()
	defer session.Close()
	if err := session.Begin(); err != nil {
		return false, err
	}
	rollback := func(err error) (bool, error) {
		_ = session.Rollback()
		return false, err
	}
	owners := map[string]bool{}
	for _, user := range users {
		owners[user.Owner] = true
	}
	ownerNames := make([]string, 0, len(owners))
	for owner := range owners {
		ownerNames = append(ownerNames, owner)
	}
	sort.Strings(ownerNames)
	for _, owner := range ownerNames {
		if err := lockGovernanceScope(session, owner); err != nil {
			return rollback(err)
		}
	}
	dependencies, err := getUserIdentityDependenciesInSession(session, users, false)
	if err != nil {
		return rollback(err)
	}
	for _, user := range users {
		if dependency := dependencies[user.GetId()]; dependency != "" {
			return rollback(fmt.Errorf("the user cannot be added while an existing %s depends on the same identity: %s", dependency, user.GetId()))
		}
		if err := CheckUserSodInSession(session, nil, user, ""); err != nil {
			return rollback(err)
		}
	}
	affected, err := session.Insert(users)
	if err != nil {
		if !strings.Contains(err.Error(), "Duplicate entry") {
			return rollback(err)
		}
		_ = session.Rollback()
		return false, nil
	}
	for _, user := range users {
		if err = userEnforcer.replaceGroupsForUserInSession(session, user.GetId(), user.Groups); err != nil {
			return rollback(err)
		}
	}
	if err = session.Commit(); err != nil {
		return rollback(err)
	}
	if err = userEnforcer.publishCommittedGroups(); err != nil {
		return false, err
	}

	return affected != 0, nil
}

func AddUsersInBatch(users []*User) (bool, error) {
	if len(users) == 0 {
		return false, fmt.Errorf("no users are provided")
	}

	batchSize := conf.GetConfigBatchSize()

	affected := false
	for i := 0; i < len(users); i += batchSize {
		start := i
		end := i + batchSize
		if end > len(users) {
			end = len(users)
		}

		tmp := users[start:end]
		fmt.Printf("The syncer adds users: [%d - %d]\n", start, end)
		if ok, err := AddUsers(tmp); err != nil {
			return false, err
		} else if ok {
			affected = true
		}
	}

	// too many users to queue one by one, the applications of their organizations are reconciled instead
	owners := map[string]bool{}
	for _, user := range users {
		if !owners[user.Owner] {
			owners[user.Owner] = true
			requestOrganizationProvisioning(user.Owner)
		}
	}
	return affected, nil
}

func deleteUser(user *User) (bool, error) {
	return deleteUserWithGovernance(user, false)
}

func deleteUserWithGovernance(user *User, prepare bool) (bool, error) {
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err := session.Begin(); err != nil {
		return false, err
	}
	rollback := func(err error) (bool, error) {
		_ = session.Rollback()
		return false, err
	}
	if err := lockGovernanceScope(session, user.Owner); err != nil {
		return rollback(err)
	}
	stored := &User{Owner: user.Owner, Name: user.Name}
	existed, err := session.ForUpdate().Get(stored)
	if err != nil {
		return rollback(err)
	}
	if !existed {
		_ = session.Rollback()
		return false, nil
	}
	dependency, err := getUserIdentityDependencyInSession(session, stored, false)
	if err != nil {
		return rollback(err)
	}
	if dependency != "" {
		return rollback(fmt.Errorf("the user cannot be deleted while a %s depends on it: %s", dependency, stored.GetId()))
	}
	if prepare {
		if err = prepareUserDeletion(stored); err != nil {
			return rollback(err)
		}
	}
	if err = deleteUserAuthenticationArtifactsInSession(session, stored); err != nil {
		return rollback(err)
	}
	affected, err := session.ID(core.PK{stored.Owner, stored.Name}).Delete(&User{})
	if err != nil {
		return rollback(err)
	}
	if err = session.Commit(); err != nil {
		return rollback(err)
	}

	return affected != 0, nil
}

// isUserAccessRevoked checks whether an update has just forbidden or soft-deleted the user, the
// columns are the ones the update actually wrote, a nil value means that all of them were written
func isUserAccessRevoked(oldUser *User, user *User, columns []string) bool {
	if oldUser.IsForbidden || oldUser.IsDeleted {
		return false
	}

	if user.IsForbidden && (columns == nil || util.InSlice(columns, "is_forbidden")) {
		return true
	}
	if user.IsDeleted && (columns == nil || util.InSlice(columns, "is_deleted")) {
		return true
	}

	return false
}

// triggerUserForbiddenWebhook sends a dedicated "forbid-user" or "unforbid-user" event once the
// update is saved, it covers every caller (API, syncers, LDAP) and not only the "update-user" API
func triggerUserForbiddenWebhook(oldUser *User, user *User, columns []string) {
	if columns != nil && !util.InSlice(columns, "is_forbidden") {
		return
	}
	if oldUser.IsForbidden == user.IsForbidden {
		return
	}

	if user.IsForbidden {
		TriggerWebhookForUser("forbid-user", user)
	} else {
		TriggerWebhookForUser("unforbid-user", user)
	}
}

// TerminateUserAccess forces the user offline, it expires the user's tokens and drops all of its
// sessions, in the same way as the "logout from all applications" flow. It does nothing when the
// user has neither active tokens nor sessions, so it is safe to call it more than once
func TerminateUserAccess(user *User) error {
	tokens, err := GetActiveTokensByUser(user.Owner, user.Name)
	if err != nil {
		return err
	}

	sessions, err := GetUserSessions(user.Owner, user.Name)
	if err != nil {
		return err
	}

	if len(tokens) == 0 && len(sessions) == 0 {
		return nil
	}

	// The ids are collected for the SSO logout notification below, the Beego sessions
	// themselves are destroyed by DeleteAllUserSessions()
	sessionIds := []string{}
	for _, session := range sessions {
		sessionIds = append(sessionIds, session.SessionId...)
	}

	// There is no request host here, the logout token and LogoutRequest take the issuer the sign-in was made with
	sendBackchannelLogoutForTokens(user, tokens, "", "")
	SendSamlLogout(user.Owner, user.Name, nil, "")

	_, err = ExpireTokenByUser(user.Owner, user.Name)
	if err != nil {
		return err
	}

	// The sessions are stored under the applications used at login, so all of them have to be
	// dropped and not only the "app-built-in" one
	_, err = DeleteAllUserSessions(user.Owner, user.Name)
	if err != nil {
		return err
	}

	// The notification is best-effort, the access has already been revoked at this point, so a
	// slow or failing notification provider must not block or undo it
	go func() {
		_ = SendSsoLogoutNotifications(user, sessionIds, tokens)
	}()

	return nil
}

func prepareUserDeletion(user *User) error {
	// Forced offline the user first, its tokens would otherwise outlive the user row
	err := TerminateUserAccess(user)
	if err != nil {
		return err
	}

	_, err = userEnforcer.DeleteGroupsForUser(user.GetId())
	if err != nil {
		return err
	}

	_, err = DeleteThirdPartyLinksByUser(user.Owner, user.Name)
	if err != nil {
		return err
	}

	err = DeletePasswordHistoryByUser(user.Owner, user.Name)
	if err != nil {
		return err
	}
	return nil
}

func deleteUserPermanentlyForMerge(user *User) (bool, error) {
	return deleteUserWithGovernance(user, true)
}

func DeleteUser(user *User) (bool, error) {
	organization, err := GetOrganizationByUser(user)
	if err != nil {
		return false, err
	}
	if organization != nil && organization.EnableSoftDeletion {
		oldUser, err := getUser(user.Owner, user.Name)
		if err != nil {
			return false, err
		}

		// Deleting a user that is already soft-deleted removes it permanently
		if oldUser != nil && !oldUser.IsDeleted {
			if err = prepareUserDeletion(oldUser); err != nil {
				return false, err
			}
			user.IsDeleted = true
			user.DeletedTime = util.GetCurrentTime()
			return UpdateUser(user.GetId(), user, []string{"is_deleted", "deleted_time"}, false)
		}
	}

	affected, err := deleteUserWithGovernance(user, true)
	if err == nil && affected {
		provisionUser(user)
	}
	return affected, err
}

func GetUserInfo(user *User, scope string, aud string, host string) (*Userinfo, error) {
	// Build a TokenFields whitelist from the application config.
	// If the application has no TokenFields configured (empty list), all fields are allowed.
	application, err := GetApplicationByClientId(aud)
	if err != nil {
		return nil, err
	}

	issuer, err := GetOidcIssuerByApplication(host, application)
	if err != nil {
		return nil, err
	}

	resp := Userinfo{
		Sub: user.Id,
		Iss: issuer,
		Aud: aud,
	}
	allowedFields := make(map[string]bool)
	hasWhitelist := application != nil && len(application.TokenFields) > 0
	if hasWhitelist {
		for _, f := range application.TokenFields {
			allowedFields[f] = true
		}
	}
	allowed := func(field string) bool {
		if !hasWhitelist {
			return true
		}
		return allowedFields[field]
	}

	if strings.Contains(scope, "profile") {
		if allowed("Name") {
			resp.Name = user.Name
		}
		if allowed("DisplayName") {
			resp.DisplayName = user.DisplayName
		}
		if allowed("Avatar") {
			resp.Avatar = user.Avatar
		}
		if allowed("Groups") {
			groups, err := user.GetGroupsForToken(application)
			if err != nil {
				return nil, err
			}
			resp.Groups = groups
		}

		if allowed("Roles") || allowed("Permissions") {
			err := ExtendUserWithRolesAndPermissions(user)
			if err != nil {
				return nil, err
			}

			if allowed("Roles") {
				resp.Roles = []string{}
				for _, role := range user.Roles {
					resp.Roles = append(resp.Roles, role.Name)
				}
			}

			if allowed("Permissions") {
				resp.Permissions = []string{}
				for _, permission := range user.Permissions {
					resp.Permissions = append(resp.Permissions, permission.Name)
				}
			}
		}
	}

	if strings.Contains(scope, "email") && allowed("Email") {
		resp.Email = user.Email
		resp.EmailVerified = user.EmailVerified
	}

	if strings.Contains(scope, "address") && allowed("Location") {
		resp.Address = getOIDCAddress(user)
	}

	if strings.Contains(scope, "phone") && allowed("Phone") {
		resp.Phone = user.Phone
		if phoneNumber, ok := util.GetE164Number(user.Phone, user.CountryCode); ok {
			resp.PhoneNumber = phoneNumber
		}
	}

	if strings.Contains(scope, "profile") {
		if allowed("RealName") {
			resp.RealName = user.RealName
		}
		if allowed("IsVerified") {
			resp.IsVerified = user.IsVerified
		}
	}

	if application != nil && application.TokenFormat == "JWT-Custom" && len(application.TokenAttributes) > 0 {
		tokenUser := *user
		err = ExtendUserWithRolesAndPermissions(&tokenUser)
		if err != nil {
			return nil, err
		}

		refinedUser, err := getTokenUser(application, &tokenUser)
		if err != nil {
			return nil, err
		}
		resp.CustomClaims = getTokenAttributeClaims(refinedUser, application.TokenAttributes)
	}

	return &resp, nil
}

func LinkUserAccount(user *User, field string, value string) (bool, error) {
	return SetUserField(user, field, value)
}

func LinkFlexibleCustomAccount(user *User, providerName string, providerId string) (bool, error) {
	if providerId == "" {
		return DeleteThirdPartyLink(user.Owner, user.Name, providerName)
	}
	link := &ThirdPartyLink{
		Owner:        user.Owner,
		UserName:     user.Name,
		ProviderName: providerName,
		ProviderId:   providerId,
	}
	return AddThirdPartyLink(link)
}

func (user *User) GetId() string {
	return fmt.Sprintf("%s/%s", user.Owner, user.Name)
}

func (user *User) PopulateThirdPartyLinks() error {
	links, err := GetThirdPartyLinksByUser(user.Owner, user.Name)
	if err != nil {
		return err
	}
	user.ThirdPartyLinks = links
	return nil
}

func (user *User) GetFriendlyName() string {
	if user.FirstName != "" && user.LastName != "" {
		return fmt.Sprintf("%s, %s", user.FirstName, user.LastName)
	} else if user.DisplayName != "" {
		return user.DisplayName
	} else if user.Name != "" {
		return user.Name
	} else {
		return user.Id
	}
}

func isUserIdGlobalAdmin(userId string) (bool, error) {
	if strings.HasPrefix(userId, "built-in/") {
		return true, nil
	}

	appUser, err := GetAppUser(userId)
	if err != nil {
		return false, err
	}
	return appUser.IsGlobalAdmin(), nil
}

func ExtendUserWithRolesAndPermissions(user *User) (err error) {
	if user == nil {
		return
	}

	user.Permissions, user.Roles, err = getPermissionsAndRolesByUser(user.GetId())
	if err != nil {
		return err
	}

	if user.Groups == nil {
		user.Groups = []string{}
	}

	return
}

func DeleteGroupForUser(user string, group string) (bool, error) {
	owner, name, err := util.GetOwnerAndNameFromIdWithError(user)
	if err != nil {
		return false, err
	}
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err = session.Begin(); err != nil {
		return false, err
	}
	rollback := func(err error) (bool, error) {
		_ = session.Rollback()
		return false, err
	}
	if err = lockGovernanceScope(session, owner); err != nil {
		return rollback(err)
	}
	userObj := &User{Owner: owner, Name: name}
	existed, err := session.ForUpdate().Get(userObj)
	if err != nil {
		return rollback(err)
	}
	if !existed {
		_ = session.Rollback()
		return false, fmt.Errorf(i18n.Translate("en", "general:The user: %s doesn't exist"), user)
	}
	oldGroups := append([]string{}, userObj.Groups...)
	userObj.Groups = util.DeleteVal(userObj.Groups, group)
	if util.StructToJson(oldGroups) == util.StructToJson(userObj.Groups) {
		_ = session.Rollback()
		return false, nil
	}
	if err = userObj.UpdateUserHash(); err != nil {
		return rollback(err)
	}
	if _, err = session.ID(core.PK{owner, name}).Cols("groups", "hash").Update(userObj); err != nil {
		return rollback(err)
	}
	if err = userEnforcer.replaceGroupsForUserInSession(session, userObj.GetId(), userObj.Groups); err != nil {
		return rollback(err)
	}
	if err = session.Commit(); err != nil {
		return rollback(err)
	}
	if err = userEnforcer.publishCommittedGroups(); err != nil {
		return false, err
	}
	return true, nil
}

func moveUserIdentityReferencesInSession(session *xorm.Session, oldUser *User, newName string) error {
	owner, oldName := oldUser.Owner, oldUser.Name
	dependency, err := getUserIdentityDependencyInSession(session, oldUser, true)
	if err != nil {
		return err
	}
	if dependency != "" {
		return fmt.Errorf("the user cannot be renamed while a %s depends on it: %s", dependency, oldUser.GetId())
	}
	destinationUser := &User{Owner: owner, Name: newName}
	destinationExists, err := session.ForUpdate().Get(destinationUser)
	if err != nil {
		return err
	}
	if destinationExists {
		return fmt.Errorf("the user cannot be renamed because the destination identity already exists: %s", destinationUser.GetId())
	}
	destinationDependency, err := getUserIdentityDependencyInSession(session, destinationUser, false)
	if err != nil {
		return err
	}
	if destinationDependency != "" {
		return fmt.Errorf("the user cannot be renamed while an existing %s depends on the destination identity: %s", destinationDependency, destinationUser.GetId())
	}

	var roles []*Role
	err = session.Find(&roles)
	if err != nil {
		return err
	}

	for _, role := range roles {
		changed := false
		for j, u := range role.Users {
			// u = organization/username
			roleOwner, roleName, err := util.GetOwnerAndNameFromIdWithError(u)
			if err != nil {
				return err
			}
			if roleOwner == owner && roleName == oldName {
				role.Users[j] = util.GetId(roleOwner, newName)
				changed = true
			}
		}
		if !changed {
			continue
		}
		_, err = session.Where("name=?", role.Name).And("owner=?", role.Owner).Update(role)
		if err != nil {
			return err
		}
	}

	_, err = session.Where(fmt.Sprintf("owner = ? AND %s = ?", quoteColumn("user")), owner, oldName).Cols("user").Update(&Resource{User: newName})
	if err != nil {
		return err
	}

	_, err = session.Where(fmt.Sprintf("organization = ? AND %s = ?", quoteColumn("user")), owner, oldName).Cols("user").Update(&Token{User: newName})
	if err != nil {
		return err
	}

	_, err = session.Where("owner = ? AND user_name = ?", owner, oldName).Cols("user_name").Update(&ThirdPartyLink{UserName: newName})
	if err != nil {
		return err
	}

	_, err = session.Where("owner = ? AND name = ?", owner, oldName).Cols("name").Update(&PasswordHistory{Name: newName})
	if err != nil {
		return err
	}

	return nil
}

func hasPermissionUsingUserInSession(session *xorm.Session, userId string) (bool, error) {
	permissions := []*Permission{}
	if err := session.Cols("users").Find(&permissions); err != nil {
		return false, err
	}
	for _, permission := range permissions {
		if util.InSlice(permission.Users, userId) {
			return true, nil
		}
	}
	return false, nil
}

// getUserIdentityDependencyInSession returns a live authorization or ownership record that
// would be inherited by a later user with the same organization/name identity. A rename may
// skip roles and resources because moveUserIdentityReferencesInSession migrates both in the same transaction.
// Historical/audit records intentionally do not reserve an identity.
func getUserIdentityDependencyInSession(session *xorm.Session, user *User, rename bool) (string, error) {
	dependencies, err := getUserIdentityDependenciesInSession(session, []*User{user}, rename)
	if err != nil {
		return "", err
	}
	return dependencies[user.GetId()], nil
}

// getUserIdentityDependenciesInSession loads every selector once so syncer/batch imports do
// not rescan all governance records for every user in the batch.
func getUserIdentityDependenciesInSession(session *xorm.Session, users []*User, rename bool) (map[string]string, error) {
	dependencies := map[string]string{}
	targets := map[string]*User{}
	owners := []string{}
	ownerSeen := map[string]bool{}
	for _, user := range users {
		if user == nil || user.Owner == "" || user.Name == "" {
			continue
		}
		targets[user.GetId()] = user
		if !ownerSeen[user.Owner] {
			ownerSeen[user.Owner] = true
			owners = append(owners, user.Owner)
		}
	}
	if len(targets) == 0 {
		return dependencies, nil
	}
	setById := func(id string, dependency string) {
		if _, targeted := targets[id]; targeted && dependencies[id] == "" {
			dependencies[id] = dependency
		}
	}
	setByName := func(owner string, name string, dependency string) {
		setById(util.GetId(owner, name), dependency)
	}

	permissions := []*Permission{}
	if err := session.Cols("users").Find(&permissions); err != nil {
		return nil, err
	}
	for _, permission := range permissions {
		for _, id := range permission.Users {
			setById(id, "permission")
		}
	}

	if !rename {
		roles := []*Role{}
		if err := session.Cols("users").Find(&roles); err != nil {
			return nil, err
		}
		for _, role := range roles {
			for _, id := range role.Users {
				setById(id, "role")
			}
		}
	}

	organizations := []*Organization{}
	if err := session.Cols("name", "enterprise_policy").Where("owner = ?", "admin").In("name", owners).Find(&organizations); err != nil {
		return nil, err
	}
	for _, organization := range organizations {
		policy := organization.EnterprisePolicy
		if policy == nil {
			continue
		}
		for _, adminNames := range [][]string{policy.SystemAdmins, policy.SecurityAdmins, policy.AuditAdmins} {
			for _, name := range adminNames {
				setByName(organization.Name, name, "enterprise administrator policy")
			}
		}
		for _, delegatedAdmin := range policy.DelegatedAdmins {
			if delegatedAdmin != nil {
				setByName(organization.Name, delegatedAdmin.User, "delegated administrator policy")
			}
		}
	}

	applications := []*Application{}
	if err := session.Cols("external_users").Find(&applications); err != nil {
		return nil, err
	}
	for _, application := range applications {
		for _, id := range application.ExternalUsers {
			setById(id, "external application grant")
		}
	}

	accounts := []*PrivilegedAccount{}
	if err := session.Cols("owner", "users", "approvers").In("owner", owners).Find(&accounts); err != nil {
		return nil, err
	}
	for _, account := range accounts {
		for _, name := range account.Users {
			setByName(account.Owner, name, "privileged account policy")
		}
		for _, name := range account.Approvers {
			setByName(account.Owner, name, "privileged account policy")
		}
	}

	requests := []*PrivilegedRequest{}
	if err := session.Cols("owner", "requester").In("owner", owners).In("state", []string{PamStatePending, PamStateApproved, PamStateActive}).Find(&requests); err != nil {
		return nil, err
	}
	for _, request := range requests {
		setByName(request.Owner, request.Requester, "active privileged access request")
	}

	subscriptions := []*Subscription{}
	if err := session.Cols("owner", "user").In("owner", owners).Find(&subscriptions); err != nil {
		return nil, err
	}
	for _, subscription := range subscriptions {
		setByName(subscription.Owner, subscription.User, "subscription")
	}

	keys := []*Key{}
	if err := session.Cols("organization", "user").In("organization", owners).Find(&keys); err != nil {
		return nil, err
	}
	for _, key := range keys {
		setByName(key.Organization, key.User, "access key")
	}

	if !rename {
		resources := []*Resource{}
		if err := session.Cols("owner", "user").In("owner", owners).Find(&resources); err != nil {
			return nil, err
		}
		for _, resource := range resources {
			setByName(resource.Owner, resource.User, "resource")
		}
	}

	pricings := []*Pricing{}
	if err := session.Cols("owner", "users").In("owner", owners).Find(&pricings); err != nil {
		return nil, err
	}
	for _, pricing := range pricings {
		for _, name := range pricing.Users {
			setByName(pricing.Owner, name, "invite-only pricing")
		}
	}

	coupons := []*Coupon{}
	if err := session.Cols("owner", "users").In("owner", owners).Find(&coupons); err != nil {
		return nil, err
	}
	for _, coupon := range coupons {
		for _, name := range coupon.Users {
			setByName(coupon.Owner, name, "user-scoped coupon")
		}
	}

	return dependencies, nil
}

func deleteUserAuthenticationArtifactsInSession(session *xorm.Session, user *User) error {
	if _, err := session.Where(fmt.Sprintf("%s = ?", quoteColumn("user")), user.GetId()).Delete(&CertLoginTicket{}); err != nil {
		return err
	}
	if _, err := session.Where(fmt.Sprintf("owner = ? and %s = ?", quoteColumn("user")), user.Owner, user.GetId()).Delete(&VerificationRecord{}); err != nil {
		return err
	}
	if user.Email != "" {
		if _, err := session.Where("owner = ? and email = ?", user.Owner, user.Email).Delete(&MagicLink{}); err != nil {
			return err
		}
	}
	return nil
}

func (user *User) IsMfaEnabled() bool {
	if user == nil {
		return false
	}
	return user.PreferredMfaType != ""
}

func (user *User) GetPreferredMfaProps(masked bool) *MfaProps {
	if user == nil || user.PreferredMfaType == "" {
		return nil
	}
	return user.GetMfaProps(user.PreferredMfaType, masked)
}

func (user *User) IsGlobalAdmin() bool {
	if user == nil {
		return false
	}

	return user.Owner == "built-in"
}

func (user *User) HasFaceIdImage() bool {
	for _, userFaceId := range user.FaceIds {
		if userFaceId.ImageUrl != "" {
			return true
		}
	}
	return false
}

const maxFaceIdImageSize = 10 << 20

// getFaceIdImage fetches a face image the user set the URL of, so it must not reach the intranet,
// except for the files uploaded to the "Local File System" storage, which are read from disk
func getFaceIdImage(imageUrl string) ([]byte, error) {
	if data, ok := readLocalUploadedFile(imageUrl); ok {
		return data, nil
	}

	resp, err := util.NewInternetOnlyHttpClient(30 * time.Second).Get(imageUrl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(io.LimitReader(resp.Body, maxFaceIdImageSize))
}

func readLocalUploadedFile(fileUrl string) ([]byte, bool) {
	urlObj, err := url.Parse(fileUrl)
	if err != nil {
		return nil, false
	}

	filePath := strings.TrimPrefix(urlObj.Path, "/files/")
	if filePath == urlObj.Path || !filepath.IsLocal(filePath) {
		return nil, false
	}

	data, err := os.ReadFile(filepath.Join("files", filePath))
	return data, err == nil
}

func (user *User) CheckUserFace(faceIdImage []string, provider *Provider) (bool, error) {
	faceIdChecker := faceId.GetFaceIdProvider(provider.Type, provider.ClientId, provider.ClientSecret, provider.Endpoint)
	errList := []error{}
	for _, userFaceId := range user.FaceIds {
		if userFaceId.ImageUrl != "" {
			imgByte, err := getFaceIdImage(userFaceId.ImageUrl)
			if err != nil {
				continue
			}

			base64Img := base64.StdEncoding.EncodeToString(imgByte)
			for _, imgBase64 := range faceIdImage {
				isSuccess, err := faceIdChecker.Check(imgBase64, base64Img)
				if err != nil {
					errList = append(errList, err)
					continue
				}
				if isSuccess {
					return true, nil
				}
			}
		}
	}
	if len(errList) > 0 {
		return false, errList[0]
	}
	return false, nil
}

func (user *User) GetUserFullGroupPath() ([]string, error) {
	if len(user.Groups) == 0 {
		return []string{}, nil
	}

	var orgGroups []*Group
	orgGroups, err := GetGroups(user.Owner)
	if err != nil {
		return nil, err
	}

	groupMap := make(map[string]Group)
	for _, group := range orgGroups {
		groupMap[group.Name] = *group
	}

	var groupFullPath []string

	for _, groupId := range user.Groups {
		_, groupName := util.GetOwnerAndNameFromIdNoCheck(groupId)
		group, ok := groupMap[groupName]
		if !ok {
			continue
		}

		groupPath := groupName
		curGroup := group
		for !curGroup.IsTopGroup {
			parentGroup, ok := groupMap[curGroup.ParentId]
			if !ok {
				return []string{}, fmt.Errorf(i18n.Translate("en", "auth:The group: %s does not exist"), curGroup.ParentId)
			}

			groupPath = util.GetId(parentGroup.Name, groupPath)
			curGroup = parentGroup
		}

		groupPath = util.GetId(curGroup.Owner, groupPath)
		groupFullPath = append(groupFullPath, groupPath)
	}

	return groupFullPath, nil
}

func (user *User) GetUserGroupNames() []string {
	groupNames := []string{}
	for _, groupId := range user.Groups {
		_, groupName := util.GetOwnerAndNameFromIdNoCheck(groupId)
		groupNames = append(groupNames, groupName)
	}
	return groupNames
}

func (user *User) GetGroupsForToken(application *Application) ([]string, error) {
	tokenGroupFormat := ""
	if application != nil {
		tokenGroupFormat = application.TokenGroupFormat
	}

	switch tokenGroupFormat {
	case "Path":
		return user.GetUserFullGroupPath()
	case "Name":
		return user.GetUserGroupNames(), nil
	default:
		return user.Groups, nil
	}
}

func GenerateIdForNewUser(application *Application) (string, error) {
	if application == nil || application.GetSignupItemRule("ID") != "Incremental" {
		return util.GenerateId(), nil
	}

	lastUser, err := getLastUser(application.Organization)
	if err != nil {
		return "", err
	}

	lastUserId := -1
	if lastUser != nil {
		lastUserId, err = util.ParseIntWithError(lastUser.Id)
		if err != nil {
			return util.GenerateId(), nil
		}
	}

	res := strconv.Itoa(lastUserId + 1)
	return res, nil
}

func UpdateUserBalance(owner string, name string, balance float64, currency string, lang string) error {
	user, err := getUser(owner, name)
	if err != nil {
		return err
	}
	if user == nil {
		return fmt.Errorf(i18n.Translate(lang, "general:The user: %s is not found"), fmt.Sprintf("%s/%s", owner, name))
	}

	// Convert the balance amount from transaction currency to user's balance currency
	balanceCurrency := user.BalanceCurrency
	var org *Organization
	if balanceCurrency == "" {
		// Get organization's balance currency as fallback
		org, err = getOrganization("admin", owner)
		if err == nil && org != nil && org.BalanceCurrency != "" {
			balanceCurrency = org.BalanceCurrency
		} else {
			balanceCurrency = "USD"
		}
	}
	convertedBalance := ConvertCurrency(balance, currency, balanceCurrency)

	// Calculate new balance
	newBalance := AddPrices(user.Balance, convertedBalance)

	// Check balance credit limit
	// User.BalanceCredit takes precedence over Organization.BalanceCredit
	var balanceCredit float64
	if user.BalanceCredit != 0 {
		balanceCredit = user.BalanceCredit
	} else {
		// Get organization's balance credit as fallback
		if org == nil {
			org, err = getOrganization("admin", owner)
			if err != nil {
				return err
			}
		}
		if org != nil {
			balanceCredit = org.BalanceCredit
		}
	}

	affected, err := incrBalance(ormer.Engine.ID(core.PK{owner, name}), "balance", convertedBalance, balanceCredit, &User{UpdatedTime: util.GetCurrentTime()})
	if err != nil {
		return err
	}
	if !affected {
		return fmt.Errorf(i18n.Translate(lang, "general:Insufficient balance: new balance %v would be below credit limit %v"), newBalance, balanceCredit)
	}
	return nil
}

// incrBalance adds amount to the column in one statement, a spending is only applied while the
// column stays at or above the credit, so concurrent payments cannot both spend the same balance
func incrBalance(session *xorm.Session, column string, amount float64, credit float64, bean interface{}) (bool, error) {
	if amount == 0 {
		return true, nil
	}
	if amount < 0 {
		session = session.Where(fmt.Sprintf("%s + ? >= ?", column), amount, credit)
	}

	affected, err := session.Incr(column, amount).Update(bean)
	return affected != 0, err
}
