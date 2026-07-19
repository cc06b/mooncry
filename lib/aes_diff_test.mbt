///|
fn aes_cbc_hex(pt : Bytes, key : Bytes, iv : Bytes) -> String {
  bytes_to_hex(aes_encrypt_cbc(pt, key, iv))
}

///|
fn aes_gcm_ct_hex(pt : Bytes, key : Bytes, iv : Bytes, aad : Bytes) -> String {
  let (c, _) = aes_gcm_encrypt(pt, key, iv, aad)
  bytes_to_hex(c)
}

///|
fn aes_gcm_tag_hex(pt : Bytes, key : Bytes, iv : Bytes, aad : Bytes) -> String {
  let (_, t) = aes_gcm_encrypt(pt, key, iv, aad)
  bytes_to_hex(t)
}

///|
fn aes_ctr_hex(pt : Bytes, key : Bytes, iv : Bytes) -> String {
  bytes_to_hex(aes_ctr(pt, key, iv))
}

///|
test "AES-CBC diff 0" {
  assert_true(
    aes_cbc_hex(
      hex_to_bytes("6e"),
      hex_to_bytes("debb52686ca0e77dd5e2185260ca881f"),
      hex_to_bytes("ae00112d56a2c3bfcd5e6df022b988c9"),
    ) ==
    "ae00112d56a2c3bfcd5e6df022b988c908149ee3263f676b2e29f846c47b5b60",
  )
}

///|
test "AES-CBC diff 1" {
  assert_true(
    aes_cbc_hex(
      hex_to_bytes("5397b94f6d95d99ad313c705df25"),
      hex_to_bytes(
        "040cac6eafcc7006f6b2ee7209e3ca190e01dc1638870477d7a93307796fac56",
      ),
      hex_to_bytes("95eb6e38d70a06e3ffa6d8af12f058b8"),
    ) ==
    "95eb6e38d70a06e3ffa6d8af12f058b894a13ad4d9e0d9aa1ab607ae91d63e10",
  )
}

///|
test "AES-CBC diff 2" {
  assert_true(
    aes_cbc_hex(
      hex_to_bytes("7807871d300e3a950a38a785f1db176168f8dfae7efa038b907dab"),
      hex_to_bytes("95ebb9b34f905b1b7324ea66aa308003"),
      hex_to_bytes("d245f5d12edf02d7f6190f6a6148705a"),
    ) ==
    "d245f5d12edf02d7f6190f6a6148705a4dfe51d54bf7975e1852f8e6083b694eb26819ea422d309943a698e77d317dd8",
  )
}

///|
test "AES-CBC diff 3" {
  assert_true(
    aes_cbc_hex(
      hex_to_bytes(
        "4dc4b3cbbcb62dbd3f2f125601aac5aa6545eb9aaa588ebef09a0714d068160b873839e2ececca42",
      ),
      hex_to_bytes(
        "5ed480df282350dea2dcd275df446f553dd70bb6106883d6dfbaca94568d5336",
      ),
      hex_to_bytes("9a4cd187c522b2d5e6b7f1b90f5627ae"),
    ) ==
    "9a4cd187c522b2d5e6b7f1b90f5627ae890254e8d839a500b9dcc537d88cd49018db98de2a583defe4fbf3b3b1d666bcae1d5b662ff08ff692c189cd633f258d",
  )
}

///|
test "AES-CBC diff 4" {
  assert_true(
    aes_cbc_hex(
      hex_to_bytes(
        "2d0781b180feaddfdd05df6e38dcd27a1620d0bfc8762690b28aed63fe12e06ccb55eea5ff1467b8248fb8b27787c630949bd6629c",
      ),
      hex_to_bytes("93ed3a804076f66508a39fef7ad97428"),
      hex_to_bytes("504531bd1ca6245384cd0cdd3ee6f346"),
    ) ==
    "504531bd1ca6245384cd0cdd3ee6f346ba0dbd7a53d323773ae309673b24359b791795ecae4306d68516ac72c85b705149d21897e282dbe150cbb4d28f1078867701b6b8f10417801d9891bade454cbe",
  )
}

///|
test "AES-CBC diff 5" {
  assert_true(
    aes_cbc_hex(
      hex_to_bytes(
        "14a4b4b513e27415c259a92916c055e119ac6f33a4f5c93a88467fe500b29babb3a662a2b2249b9341bb00311cb1216a8d70ffeb7644aa88a385e1b1803ff8e690b1",
      ),
      hex_to_bytes(
        "17d2c4b56e6e4c06dcd2fe638f07b478d1d7afd3dc3473467a192a3e3d147af9",
      ),
      hex_to_bytes("8b047e20430b187240aec89481d06a64"),
    ) ==
    "8b047e20430b187240aec89481d06a6436e9302bf55c7e854175e92897a0ea4d9debd079a570a356cd54256fbe9022c4fb5cad5bb434518bb70233e50c5da622e70c85e11237a258eed256263d05905c44fe2e56ac131f474b7c5e4a46589016",
  )
}

///|
test "AES-CBC diff 6" {
  assert_true(
    aes_cbc_hex(
      hex_to_bytes(
        "e73849c89da822d625f6a9bcd7095c0a8df97775d1af4633c08479a607d6e29985c0756bf01a4aba66b039affdc5cf46d31f426d810bd0c350ca306372535e0e266b073a6d9189259768346c997bc9",
      ),
      hex_to_bytes("0538c5dbd9bec4cd83464b65d4f975b5"),
      hex_to_bytes("f0ddb65234660141cdf3292b52e1878e"),
    ) ==
    "f0ddb65234660141cdf3292b52e1878e5a2000f2af932fb18c564c14084173b864589aa5b36f2fda13d270b0d607d0de704647af2fd59b3a44aa48f6caa5a140c3a6ba3125289c0cc65c30786186eade8bd24c920509c6fe53b3831b31b78a35",
  )
}

///|
test "AES-CBC diff 7" {
  assert_true(
    aes_cbc_hex(
      hex_to_bytes(
        "f950c8963573a6554082811f398c3885b880ab13bb9a0479a76c826c376e5ab324133a77806ae32ca07c1b243fb258706b3f7b716017fd6636f30cc05931786b7f02464cd6f0ce00e21c89d260bd8e3b3b7db23b473cb0c5bd7b78cf",
      ),
      hex_to_bytes(
        "780f5cc69ffed1ddc7a9014201bdbe584f49839a999fb0f1763570622e524516",
      ),
      hex_to_bytes("53329e85d9fda58eeec04fb287e5f3cc"),
    ) ==
    "53329e85d9fda58eeec04fb287e5f3cc4491ac7acc63ccef25ad91132f70cd41e393bd2866304a8737a22a1dc5a83802d7def96cccc420fd33c39c370f0da465757347a3ff5ee96b1ff50f65ab63f6ef0638ec722b507a4de3c8a16ac2448cf4ce7026a36898eff946336e12be784985",
  )
}

///|
test "AES-CBC diff 8" {
  assert_true(
    aes_cbc_hex(
      hex_to_bytes(
        "94d25344d0b55283ae56d9347e559137f37b827a0a45398b7cb1b7b219bfb8ab27dc6879e09a191418ca43c9f65664a2f69cde568b74bc116f38bbf81e2942601de989336463e18c44acb685dc152c99064409d3db6ec69c292d5e043bffd1fd96ca3ea67800eb88be",
      ),
      hex_to_bytes("5610f17d1380a7323511151c68aa5c6b"),
      hex_to_bytes("728fbd18e8587d5d4b91b2107f340471"),
    ) ==
    "728fbd18e8587d5d4b91b2107f340471606cb5f0604632dd39a9b3ed25afa7f8b21a58e1442b548f8dfdeee9a15ae548943a522838222f01b8f22d83963eb63d61057b2a6ae0492b0b2739387b65e2dbb1fbaa1f3a4fea7e3797bec71d7b1a51ad4b607bfd9fae1000df7f162b4da12df0c34c23923e150119b6a5046f5f493e",
  )
}

///|
test "AES-CBC diff 9" {
  assert_true(
    aes_cbc_hex(
      hex_to_bytes(
        "be81355290eaae6f8e20c946709fbd53c7f05029927a4b72edbbf6439c31910e65d275d11182fb707c31d4ee347b0611e704dbea33026d5348d5bef5926894786c1f9b479a272ff97cde0ea930427df7e979c3b8533afb58d9f525eccd9b37022bd1c5e72b04d724e799b296c7999aa14581cda46185",
      ),
      hex_to_bytes(
        "be9189e2b53aa8a028acdce8d42f3b13f746f2d88c14ed7ff84dc5d0a03841df",
      ),
      hex_to_bytes("2966c1432af29d1ba591bd6a13e5adb1"),
    ) ==
    "2966c1432af29d1ba591bd6a13e5adb1c8d3dc38089e16df6640b42661626529362b00151378169078fce0373802df51f9984447a3eecc45ec2a06c639bf06f7b5ee5bd0f8ce36ba8cc72b6a6f2d5b2f357aae05cd32a19e2e8e55d647c1e9d8ce28111ef3c1b276ac3e1fa1a52a1a7fb75805d31503add644e3757f9716fc63d442f56f3f05a1efe9eb2c347b28ba92",
  )
}

///|
test "AES-GCM diff 10" {
  assert_true(
    aes_gcm_ct_hex(
      hex_to_bytes("61"),
      hex_to_bytes("6708a565937639e5947e32670f2496a0"),
      hex_to_bytes("ea299dccf19ba29f2919f986"),
      hex_to_bytes("ac"),
    ) ==
    "fb" &&
    aes_gcm_tag_hex(
      hex_to_bytes("61"),
      hex_to_bytes("6708a565937639e5947e32670f2496a0"),
      hex_to_bytes("ea299dccf19ba29f2919f986"),
      hex_to_bytes("ac"),
    ) ==
    "68712ce4578135a19660e3750b80fc45",
  )
}

///|
test "AES-GCM diff 11" {
  assert_true(
    aes_gcm_ct_hex(
      hex_to_bytes("ee660f36c3d36fb55e3dab9694a7"),
      hex_to_bytes(
        "0d622dc3ac8226b62ab8b2b7c54b03812f73e66d6d3d1bca44b1b0d5fc7fe47b",
      ),
      hex_to_bytes("afb524a31bca277951f256c6"),
      hex_to_bytes("efa5103a63537892"),
    ) ==
    "a010f8cc6d2d005566935ef7de6c" &&
    aes_gcm_tag_hex(
      hex_to_bytes("ee660f36c3d36fb55e3dab9694a7"),
      hex_to_bytes(
        "0d622dc3ac8226b62ab8b2b7c54b03812f73e66d6d3d1bca44b1b0d5fc7fe47b",
      ),
      hex_to_bytes("afb524a31bca277951f256c6"),
      hex_to_bytes("efa5103a63537892"),
    ) ==
    "629f9f59b0a33982ae0348378f409a74",
  )
}

///|
test "AES-GCM diff 12" {
  assert_true(
    aes_gcm_ct_hex(
      hex_to_bytes("423d6c4d5a019b8e43c9da5a00fd29103a1c69029c612c34159a45"),
      hex_to_bytes("16aeb7e985ad81dc1bf39b6eb8694a35"),
      hex_to_bytes("2eace2a6d5436cbec01070c2"),
      hex_to_bytes("c618100d01f6f31c0cc67fbaa3bd33"),
    ) ==
    "a5c6f8520bd58b20a58053d60e810288b0d80e73ee78e3f44840a6" &&
    aes_gcm_tag_hex(
      hex_to_bytes("423d6c4d5a019b8e43c9da5a00fd29103a1c69029c612c34159a45"),
      hex_to_bytes("16aeb7e985ad81dc1bf39b6eb8694a35"),
      hex_to_bytes("2eace2a6d5436cbec01070c2"),
      hex_to_bytes("c618100d01f6f31c0cc67fbaa3bd33"),
    ) ==
    "53937d9e8e274936e79bd25a998c4f3d",
  )
}

///|
test "AES-GCM diff 13" {
  assert_true(
    aes_gcm_ct_hex(
      hex_to_bytes(
        "83077ebd0bf9ad1cae5c0d02614129b94c8a69ea6a1bb2f1b4069cec8b4d67074d6668b42729328a",
      ),
      hex_to_bytes(
        "5a38a6715feab1193f5eb237d9dafefc0ce30f6fe2619c208410cf4714235821",
      ),
      hex_to_bytes("c51e346f3eb03e40e0f62e1e"),
      hex_to_bytes("22d4bc4b80a6c720e71325a2e5932aedc5b89a463a0b"),
    ) ==
    "7af65a4c78a9206697eb7df111753d3c7040ca2983797e8f4c7dafff5371107958ce2dcebf94ce28" &&
    aes_gcm_tag_hex(
      hex_to_bytes(
        "83077ebd0bf9ad1cae5c0d02614129b94c8a69ea6a1bb2f1b4069cec8b4d67074d6668b42729328a",
      ),
      hex_to_bytes(
        "5a38a6715feab1193f5eb237d9dafefc0ce30f6fe2619c208410cf4714235821",
      ),
      hex_to_bytes("c51e346f3eb03e40e0f62e1e"),
      hex_to_bytes("22d4bc4b80a6c720e71325a2e5932aedc5b89a463a0b"),
    ) ==
    "2bc8501f0580bdaa00712601010c6136",
  )
}

///|
test "AES-GCM diff 14" {
  assert_true(
    aes_gcm_ct_hex(
      hex_to_bytes(
        "66350a8c89a2d576db89d63854256287e5b5ccd77ab6dc840593b30245cedec63e98d99e5348f91221a1482b5fb9a933abfc1c00e2",
      ),
      hex_to_bytes("a6164da0cc6cfb67205199a946904786"),
      hex_to_bytes("9a3e1ad0721c06962d484bd0"),
      hex_to_bytes("ef1c53971b6b52ed52c4e71abd602b44087f76d0c195a501d3431f0adc"),
    ) ==
    "79e29721b57b7e88cdfa60201e9c7cd46b7a4b9c16bf91278746d2739ffc53b3ff0397190925d904b91ca4948bf4dc3c0190d842b7" &&
    aes_gcm_tag_hex(
      hex_to_bytes(
        "66350a8c89a2d576db89d63854256287e5b5ccd77ab6dc840593b30245cedec63e98d99e5348f91221a1482b5fb9a933abfc1c00e2",
      ),
      hex_to_bytes("a6164da0cc6cfb67205199a946904786"),
      hex_to_bytes("9a3e1ad0721c06962d484bd0"),
      hex_to_bytes("ef1c53971b6b52ed52c4e71abd602b44087f76d0c195a501d3431f0adc"),
    ) ==
    "d3e485851c829c1d7e318dded8f725f0",
  )
}

///|
test "AES-GCM diff 15" {
  assert_true(
    aes_gcm_ct_hex(
      hex_to_bytes(
        "913e04638cf26f91e018c0859bb744cdc5632d57d3a74d4f1b3b1f08b0ab29908ab5f7141fff7a7667f3fcdefa2390caf538f83698e5091285516b01ab7a7672ca7c",
      ),
      hex_to_bytes(
        "88b85117d00b91f21726ee53e339134511e1cf65744ee221edcdab95db767237",
      ),
      hex_to_bytes("6dca506b5fbb06c8ce4e1634"),
      hex_to_bytes("30da1a50542b"),
    ) ==
    "883cea7f7f93ae3c087097fa7f534382795ee7b5bb9681a11dc0bb351ea07d4990e42f127014109e683bbfe40142070b709d9af94b7bb7855c2bf5d81ed9ce1c5edd" &&
    aes_gcm_tag_hex(
      hex_to_bytes(
        "913e04638cf26f91e018c0859bb744cdc5632d57d3a74d4f1b3b1f08b0ab29908ab5f7141fff7a7667f3fcdefa2390caf538f83698e5091285516b01ab7a7672ca7c",
      ),
      hex_to_bytes(
        "88b85117d00b91f21726ee53e339134511e1cf65744ee221edcdab95db767237",
      ),
      hex_to_bytes("6dca506b5fbb06c8ce4e1634"),
      hex_to_bytes("30da1a50542b"),
    ) ==
    "8bd41f8b204fb8474b21f6b9da91fe99",
  )
}

///|
test "AES-GCM diff 16" {
  assert_true(
    aes_gcm_ct_hex(
      hex_to_bytes(
        "a6cf3ed5eb3403cd4fe0bd2014c01d31690dfd79b7d73e8d2cba6074fd3051684515f59dc0a02331a83ae442709b7f96f44b3fcde736eb520a79cd7ebb2aee8546d39592d50a75d5fbee82db823511",
      ),
      hex_to_bytes("36712bab98a4800ea5777b40dc6b8111"),
      hex_to_bytes("f5dd87bc367b826324c4af0c"),
      hex_to_bytes("83801fe7b06a74fdd7a4a2331b"),
    ) ==
    "5aad9b07f63ebeb6b9699b1722f01ff6926bb4127f432913143ab7f803be2c355a015bc8d63ca68e8bc0c509fbb18e7bdad38f8f7c0048b60bb877494d135d5ec8c22d29a59fbd284df23e68db656b" &&
    aes_gcm_tag_hex(
      hex_to_bytes(
        "a6cf3ed5eb3403cd4fe0bd2014c01d31690dfd79b7d73e8d2cba6074fd3051684515f59dc0a02331a83ae442709b7f96f44b3fcde736eb520a79cd7ebb2aee8546d39592d50a75d5fbee82db823511",
      ),
      hex_to_bytes("36712bab98a4800ea5777b40dc6b8111"),
      hex_to_bytes("f5dd87bc367b826324c4af0c"),
      hex_to_bytes("83801fe7b06a74fdd7a4a2331b"),
    ) ==
    "985a424604cb7e00ae893a68787d0ac6",
  )
}

///|
test "AES-GCM diff 17" {
  assert_true(
    aes_gcm_ct_hex(
      hex_to_bytes(
        "526b9d96fa9ea980da57c157ab474b7361adb324e501dd9c97f7d30c35abce7bdd83b1b1aa27df70cf02704ec433ec90d70a1613b9cee2e50ee8f73647c151e43892ea17809a56b01172724f79527414eac34eaf29f2fbdb429c0440",
      ),
      hex_to_bytes(
        "ba264558b2012e2f97f739d97030e02511d6dd4e7dca8decce5037e66746b3f3",
      ),
      hex_to_bytes("db9d9d755db2b97caff57e35"),
      hex_to_bytes("3eb302ab68c37d1b9d9b6a78c3fb580d3b4d76de"),
    ) ==
    "8f30b0ddfd4eee3751ab409ec992a6c066cd40dc70a4194a850a374ffcda23b048ee7007b234d6bb1af383fd666df78688a0eca217e1c66bd73f5155a9086fdee6881f6c48f74199448be0a7a567d32249a1fb02a85d3487c6e88d3c" &&
    aes_gcm_tag_hex(
      hex_to_bytes(
        "526b9d96fa9ea980da57c157ab474b7361adb324e501dd9c97f7d30c35abce7bdd83b1b1aa27df70cf02704ec433ec90d70a1613b9cee2e50ee8f73647c151e43892ea17809a56b01172724f79527414eac34eaf29f2fbdb429c0440",
      ),
      hex_to_bytes(
        "ba264558b2012e2f97f739d97030e02511d6dd4e7dca8decce5037e66746b3f3",
      ),
      hex_to_bytes("db9d9d755db2b97caff57e35"),
      hex_to_bytes("3eb302ab68c37d1b9d9b6a78c3fb580d3b4d76de"),
    ) ==
    "a4b0bbd0740dbd90e4b50668e28205c8",
  )
}

///|
test "AES-GCM diff 18" {
  assert_true(
    aes_gcm_ct_hex(
      hex_to_bytes(
        "7dd519dad46be446da3842aeda8df48f5105b09b9907541ed17e316d509af2736102a1a08db532133994ffe0c647f05d4b8ac13f7207f085e94afc9ec16eac9f8402d66c7b104cca8aa141c6db0018711c52e779066030ee7a47de6d24faea0cb68d30c09061864859",
      ),
      hex_to_bytes("ed7f34f6a41d9b6855be650d941beb89"),
      hex_to_bytes("7e30f1865960af3335e2b43b"),
      hex_to_bytes("afcbc562963ecbe5825835cc9529220e7cf1847575968607e233b0"),
    ) ==
    "65c2c3a88f5164ca049b5bbc6eb4a41adc4a2ba166dca1c268c25df8ca559c29dba34d67c9cca90726f60df6b18f880c46b2aac822ad77f4cc570caf6b0c553c23be9bd59676c6b69fb413c05c78c9cadc9bbd0c01bd2d68f179b351d33246746e2b1b4a938a49d1a9" &&
    aes_gcm_tag_hex(
      hex_to_bytes(
        "7dd519dad46be446da3842aeda8df48f5105b09b9907541ed17e316d509af2736102a1a08db532133994ffe0c647f05d4b8ac13f7207f085e94afc9ec16eac9f8402d66c7b104cca8aa141c6db0018711c52e779066030ee7a47de6d24faea0cb68d30c09061864859",
      ),
      hex_to_bytes("ed7f34f6a41d9b6855be650d941beb89"),
      hex_to_bytes("7e30f1865960af3335e2b43b"),
      hex_to_bytes("afcbc562963ecbe5825835cc9529220e7cf1847575968607e233b0"),
    ) ==
    "35f1765fd03d3137d1f1405eb7992fbd",
  )
}

///|
test "AES-GCM diff 19" {
  assert_true(
    aes_gcm_ct_hex(
      hex_to_bytes(
        "6b71c5471d77e258cb31a40cebe7f9dde047c36b471d99fdd6209edcdf6beba10679a0da4a5d715d85efb2fb2e7a22af66dae3167f74f11890f3e9ace3b53ca188bdff68755520388763d470e10c076dd514474dd369b9aac0272727fdff3446211421edebdf044fb145112f2050b23ce0ad78fc0a64",
      ),
      hex_to_bytes(
        "37f5fcaae260175a8ac2bccf80a6a0883836427b06791da25d3bc2a8aeedd034",
      ),
      hex_to_bytes("16aa6734cddddeb6ebbcae02"),
      hex_to_bytes("c8d6a1a7"),
    ) ==
    "6e93a99b714adae80a8c1d65d1584b7eb51cc8b9f3b767de209ca504292813ae5af5dba00af6e134993a5a894b607dc4ad0bdc99af73e26da5c6eba4ffe2ddb4c9954c232b24a5b9bf8a08de8ca1ecc74020ead635302a12fb6367c2540b8851d92d0b1919a60e0c94d1accfa1af9b6ba749f3acbe6f" &&
    aes_gcm_tag_hex(
      hex_to_bytes(
        "6b71c5471d77e258cb31a40cebe7f9dde047c36b471d99fdd6209edcdf6beba10679a0da4a5d715d85efb2fb2e7a22af66dae3167f74f11890f3e9ace3b53ca188bdff68755520388763d470e10c076dd514474dd369b9aac0272727fdff3446211421edebdf044fb145112f2050b23ce0ad78fc0a64",
      ),
      hex_to_bytes(
        "37f5fcaae260175a8ac2bccf80a6a0883836427b06791da25d3bc2a8aeedd034",
      ),
      hex_to_bytes("16aa6734cddddeb6ebbcae02"),
      hex_to_bytes("c8d6a1a7"),
    ) ==
    "58cdd3b3e2f1b4b47737190c71a0a63c",
  )
}

///|
test "AES-CTR diff 20" {
  assert_true(
    aes_ctr_hex(
      hex_to_bytes("b8"),
      hex_to_bytes("c219c0b267b0ed6355a1c5a1dfbe3de9"),
      hex_to_bytes("07cad6fdc6c03549cfac5f485ae6f433"),
    ) ==
    "75",
  )
}

///|
test "AES-CTR diff 21" {
  assert_true(
    aes_ctr_hex(
      hex_to_bytes("c39f28d0f4753879612e42b019f4"),
      hex_to_bytes(
        "dd4107769f50a9383ba4c63779a5eb8a9c646507755f28f818e136d07c2b12e4",
      ),
      hex_to_bytes("584d1854259d1a472317770cd1cc22a2"),
    ) ==
    "5a5aa8e42d43b27b0f23e990859a",
  )
}

///|
test "AES-CTR diff 22" {
  assert_true(
    aes_ctr_hex(
      hex_to_bytes("f7025f20dbe6db9a71a97898846cab4fc3864ef40d6526da05aaef"),
      hex_to_bytes("43b81c71de42b9ed508dd8b289cf8354"),
      hex_to_bytes("b3e53f3461623706493f9e2f95b4ff1d"),
    ) ==
    "789d2722b6db37bc66d592145a9cc8fc3ab8b7154ef306c7a28470",
  )
}

///|
test "AES-CTR diff 23" {
  assert_true(
    aes_ctr_hex(
      hex_to_bytes(
        "71e030044cb6d94476e16a28cecda23686d7b48d146fc662dda093675ee96adfa436d579c70a41bf",
      ),
      hex_to_bytes(
        "0085a4047a0a252a6802b7f6877e83f1b0633789e0b50f4897f5cae923cbf0a8",
      ),
      hex_to_bytes("d6ad631ec32543decb04141be16b110e"),
    ) ==
    "8071ceaba81492e3b977fcac2a969645c6b89d8fa86ad1e4603c0c82cd14cf01df343f2225ee9cae",
  )
}

///|
test "AES-CTR diff 24" {
  assert_true(
    aes_ctr_hex(
      hex_to_bytes(
        "7b51d1f533588f70d892284af333d342c54a8fcece34fb17dccc77aa0dc11e914ad9c6b0aaccedee2eb4f15746eebcdbd29cd5aa5e",
      ),
      hex_to_bytes("dc09204eb1780e75b8814caf2264ef00"),
      hex_to_bytes("af20234cfb5d36afca9d3c92f1d69837"),
    ) ==
    "f2f2b43447e2173b6f22bf0aef227bf213338b93e5608555117cd0988045e2d6bf6dd0a3bdc60a0d30ce940aeb22ab541a74147d6d",
  )
}

///|
test "AES-CTR diff 25" {
  assert_true(
    aes_ctr_hex(
      hex_to_bytes(
        "f379fc4d6a4bcee395bf251bc3155301055dd92dfbf16aa4c1e798698cbc386cd52be2f5eb14ad0d64677d1d16362ee59f4c6e42870fc7e8c16b738a9c8553714c2c",
      ),
      hex_to_bytes(
        "71fd24d2e8704f7e831bf0bc0d2be7f53c6baed0970df497a559cbee8613db8a",
      ),
      hex_to_bytes("0c0222815eb97c9934d477a41ccd229b"),
    ) ==
    "bb00fec91f9b6e1668b7992898274c866721a69ba51b076327581c5dae53b8f1b73c9df0c6bf419d3e4a2e72fb1ad06f60c7f8dcb09ab39883c6afcdf0961053de34",
  )
}

///|
test "AES-CTR diff 26" {
  assert_true(
    aes_ctr_hex(
      hex_to_bytes(
        "79f063bec635fab0bfe3046d1b002433aa369142f469e910e002ff89cbb3f01895ab07a01f4868a5dd7a6e81b10719f85607f028a370d8cf4eaaccd8122f234dad44afa849a4aecf63c33d8604baa6",
      ),
      hex_to_bytes("0dbdab1537ad354e840360c61d0c1562"),
      hex_to_bytes("042fceb1bce0e767b83b251be2c088f3"),
    ) ==
    "5a7a81e96a8602d006496013b98e61c623b04295ea167c7d16d8f0e2dcb8d1e1966f3cebc4cc60f4683f098e9911b4e80ddd271e906441b40ad5f03050101e06017fffc658adb54ec371ba4b67c33e",
  )
}

///|
test "AES-CTR diff 27" {
  assert_true(
    aes_ctr_hex(
      hex_to_bytes(
        "9b475dbe159bca3b8fbec85833d2006af5f33651301e3a7a6e5dfa5d59c2c6d76adedfabc229360a97cf08cd373c11dcbb686ce1730996619ff8ae454dce49c6d1a9aaaec66b78b436731625434d64bd4618aa56826fbd44c1d67c1e",
      ),
      hex_to_bytes(
        "530a7189391ec7af95f92092335baff0d3f1a23695b0f2c8123a0aec02ab6f21",
      ),
      hex_to_bytes("bb7ec14210b7f6b6640a8313b91c4e48"),
    ) ==
    "849b5eef6e1afd76ba0707b77630f9c1255b6649f66a9d2130ba70e94e3c34da58a93d9af9257eeff24f06b150b899b024d1bca9019ceed47a2c8d4222d966a11d60292f19e898b00fff837ec37298a825f24d48e9b2a4d20d40ea92",
  )
}

///|
test "AES-CTR diff 28" {
  assert_true(
    aes_ctr_hex(
      hex_to_bytes(
        "9f464d0e74de17c531f4dd4b79f68f3b9fc6c1021ab0c91cb85faf4da07de18067e87186cedde1a8c24b129911bad193a3e882cb99753ccdce893f9c916faadbb1a1a0ef810f465eb98ac33137bbf253072631fa82132bbbd280ca05e002e7e411a055f7dee21c2acb",
      ),
      hex_to_bytes("0a8a08c026b57dda827f5dfdac4ed503"),
      hex_to_bytes("0e2c1d6cae78063a377df9285f6d87a4"),
    ) ==
    "33c30dbd19fd7edf0c674a7e176855165870e406ab1972e0b4b42ae4862676848b6229b55452ddcf766a880bb1fe48c55736f523310661a4a68316426fcf0364f48be748beb3c44aecc6a5a956a09ec1b950d8d400957dc7a433d44dc22cb06f5768de5e4258630b10",
  )
}

///|
test "AES-CTR diff 29" {
  assert_true(
    aes_ctr_hex(
      hex_to_bytes(
        "de0e29744ff540ed7fb65c9af585753c38fcf93d51f3abfed5e5d525fc1b3033be9b6ad7c0d941f6219c2473ace368a6452eca4ef5ed82982428cded6b5a1bb25835b3d1aefe3258f13f278239e9c5657f2932b25b543d56d35390a07ad272e6c526c09f09aff84f5d904a0c8ab674d4ddb8f6b5fc81",
      ),
      hex_to_bytes(
        "9ff5b840d24baaead34b9e2dde3c251f5da43b64357f0b1d1641208b8c25b176",
      ),
      hex_to_bytes("e73feee260a5a98d13f3b599950b5c41"),
    ) ==
    "e62e11cae08bfc284aba74f06bd4143b99c4828bda0dfb4ac8bcfe29f3229d210a89dd53b0eb8ed7913f1c336936d8c354552eaca5ed6214034d8ab5cb17906afb888d9d9803c7c977cc08b879fd9af174f6689198f2a46121669dc5b127ab7a0cdc70956e8f28b92153b7dd99a90348c09d79dd7fbc",
  )
}
