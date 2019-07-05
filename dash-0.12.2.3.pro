TEMPLATE = app
TARGET =
DEPENDPATH +=  \
    . \
    src/bench \
    src/compat \
    src/config \
    src/consensus \
    src/crypto \
    src/crypto/ctaes \
    src/crypto/Lyra2Z \
    src/drafted \
    src/leveldb \
    src/leveldb/db \
    src/leveldb/doc \
    src/leveldb/doc/bench \
    src/leveldb/helpers \
    src/leveldb/helpers/memenv \
    src/leveldb/include \
    src/leveldb/include/leveldb \
    src/leveldb/issues \
    src/leveldb/port \
    src/leveldb/port/win \
    src/leveldb/table \
    src/leveldb/util \
    src/obj \
    src/obj-test \
    src/policy \
    src/primitives \
    src/qt \
    src/qt/forms \
    src/qt/locale \
    src/qt/res \
    src/qt/res/css \
    src/qt/res/icons \
    src/qt/res/icons/crownium \
    src/qt/res/icons/drkblue \
    src/qt/res/icons/light \
    src/qt/res/icons/trad \
    src/qt/res/images \
    src/qt/res/images/crownium \
    src/qt/res/images/drkblue \
    src/qt/res/images/light \
    src/qt/res/images/trad \
    src/qt/res/movies \
    src/qt/res/src \
    src/qt/test \
    src/rpc \
    src/script \
    src/secp256k1 \
    src/secp256k1/build-aux \
    src/secp256k1/build-aux/m4 \
    src/secp256k1/contrib \
    src/secp256k1/include \
    src/secp256k1/obj \
    src/secp256k1/src \
    src/secp256k1/src/java \
    src/secp256k1/src/java/org \
    src/secp256k1/src/java/org/bitcoin \
    src/secp256k1/src/modules \
    src/secp256k1/src/modules/ecdh \
    src/secp256k1/src/modules/recovery \
    src/secp256k1/src/modules/schnorr \
    src/support \
    src/support/allocators \
    src/test \
    src/test/data \
    src/univalue \
    src/univalue/build-aux \
    src/univalue/build-aux/m4 \
    src/univalue/gen \
    src/univalue/include \
    src/univalue/lib \
    src/univalue/pc \
    src/univalue/test \
    src/wallet \
    src/wallet/test \
    src/zmq
INCLUDEPATH +=  \
    . \
    src/bench \
    src/compat \
    src/config \
    src/consensus \
    src/crypto \
    src/crypto/ctaes \
    src/crypto/Lyra2Z \
    src/drafted \
    src/leveldb \
    src/leveldb/db \
    src/leveldb/doc \
    src/leveldb/doc/bench \
    src/leveldb/helpers \
    src/leveldb/helpers/memenv \
    src/leveldb/include \
    src/leveldb/include/leveldb \
    src/leveldb/issues \
    src/leveldb/port \
    src/leveldb/port/win \
    src/leveldb/table \
    src/leveldb/util \
    src/obj \
    src/obj-test \
    src/policy \
    src/primitives \
    src/qt \
    src/qt/forms \
    src/qt/locale \
    src/qt/res \
    src/qt/res/css \
    src/qt/res/icons \
    src/qt/res/icons/crownium \
    src/qt/res/icons/drkblue \
    src/qt/res/icons/light \
    src/qt/res/icons/trad \
    src/qt/res/images \
    src/qt/res/images/crownium \
    src/qt/res/images/drkblue \
    src/qt/res/images/light \
    src/qt/res/images/trad \
    src/qt/res/movies \
    src/qt/res/src \
    src/qt/test \
    src/rpc \
    src/script \
    src/secp256k1 \
    src/secp256k1/build-aux \
    src/secp256k1/build-aux/m4 \
    src/secp256k1/contrib \
    src/secp256k1/include \
    src/secp256k1/obj \
    src/secp256k1/src \
    src/secp256k1/src/java \
    src/secp256k1/src/java/org \
    src/secp256k1/src/java/org/bitcoin \
    src/secp256k1/src/modules \
    src/secp256k1/src/modules/ecdh \
    src/secp256k1/src/modules/recovery \
    src/secp256k1/src/modules/schnorr \
    src/support \
    src/support/allocators \
    src/test \
    src/test/data \
    src/univalue \
    src/univalue/build-aux \
    src/univalue/build-aux/m4 \
    src/univalue/gen \
    src/univalue/include \
    src/univalue/lib \
    src/univalue/pc \
    src/univalue/test \
    src/wallet \
    src/wallet/test \
    src/zmq
HEADERS +=  \
    src/activemasternode.h \
    src/addrdb.h \
    src/addressindex.h \
    src/addrman.h \
    src/alert.h \
    src/amount.h \
    src/arith_uint256.h \
    src/base58.h \
    src/bench/bench.h \
    src/bip39.h \
    src/bip39_english.h \
    src/bloom.h \
    src/cachemap.h \
    src/cachemultimap.h \
    src/chain.h \
    src/chainparams.h \
    src/chainparamsbase.h \
    src/chainparamsseeds.h \
    src/checkpoints.h \
    src/checkqueue.h \
    src/clientversion.h \
    src/coincontrol.h \
    src/coins.h \
    src/compat/byteswap.h \
    src/compat/endian.h \
    src/compat/sanity.h \
    src/compat.h \
    src/compressor.h \
    src/consensus/consensus.h \
    src/consensus/merkle.h \
    src/consensus/params.h \
    src/consensus/validation.h \
    src/core_io.h \
    src/core_memusage.h \
    src/crypto/aes.h \
    src/crypto/common.h \
    src/crypto/ctaes/ctaes.h \
    src/crypto/hmac_sha256.h \
    src/crypto/hmac_sha512.h \
    src/crypto/Lyra2Z/Lyra2.h \
    src/crypto/Lyra2Z/Lyra2Z.h \
    src/crypto/Lyra2Z/sph_blake.h \
    src/crypto/Lyra2Z/sph_types.h \
    src/crypto/Lyra2Z/Sponge.h \
    src/crypto/ripemd160.h \
    src/crypto/scrypt.h \
    src/crypto/sha1.h \
    src/crypto/sha256.h \
    src/crypto/sha512.h \
    src/crypto/sph_blake.h \
    src/crypto/sph_bmw.h \
    src/crypto/sph_cubehash.h \
    src/crypto/sph_echo.h \
    src/crypto/sph_groestl.h \
    src/crypto/sph_jh.h \
    src/crypto/sph_keccak.h \
    src/crypto/sph_luffa.h \
    src/crypto/sph_shavite.h \
    src/crypto/sph_simd.h \
    src/crypto/sph_skein.h \
    src/crypto/sph_types.h \
    src/dbwrapper.h \
    src/drafted/governance-categories.h \
    src/drafted/governance-classes.h \
    src/drafted/governance-keys.h \
    src/drafted/governance-types.h \
    src/dsnotificationinterface.h \
    src/flat-database.h \
    src/governance-classes.h \
    src/governance-exceptions.h \
    src/governance-misc.h \
    src/governance-object.h \
    src/governance-validators.h \
    src/governance-vote.h \
    src/governance-votedb.h \
    src/governance.h \
    src/hash.h \
    src/hdchain.h \
    src/httprpc.h \
    src/httpserver.h \
    src/init.h \
    src/instantx.h \
    src/keepass.h \
    src/key.h \
    src/keystore.h \
    src/leveldb/db/builder.h \
    src/leveldb/db/dbformat.h \
    src/leveldb/db/db_impl.h \
    src/leveldb/db/db_iter.h \
    src/leveldb/db/filename.h \
    src/leveldb/db/log_format.h \
    src/leveldb/db/log_reader.h \
    src/leveldb/db/log_writer.h \
    src/leveldb/db/memtable.h \
    src/leveldb/db/skiplist.h \
    src/leveldb/db/snapshot.h \
    src/leveldb/db/table_cache.h \
    src/leveldb/db/version_edit.h \
    src/leveldb/db/version_set.h \
    src/leveldb/db/write_batch_internal.h \
    src/leveldb/helpers/memenv/memenv.h \
    src/leveldb/include/leveldb/c.h \
    src/leveldb/include/leveldb/cache.h \
    src/leveldb/include/leveldb/comparator.h \
    src/leveldb/include/leveldb/db.h \
    src/leveldb/include/leveldb/dumpfile.h \
    src/leveldb/include/leveldb/env.h \
    src/leveldb/include/leveldb/filter_policy.h \
    src/leveldb/include/leveldb/iterator.h \
    src/leveldb/include/leveldb/options.h \
    src/leveldb/include/leveldb/slice.h \
    src/leveldb/include/leveldb/status.h \
    src/leveldb/include/leveldb/table.h \
    src/leveldb/include/leveldb/table_builder.h \
    src/leveldb/include/leveldb/write_batch.h \
    src/leveldb/port/atomic_pointer.h \
    src/leveldb/port/port.h \
    src/leveldb/port/port_example.h \
    src/leveldb/port/port_posix.h \
    src/leveldb/port/port_win.h \
    src/leveldb/port/thread_annotations.h \
    src/leveldb/port/win/stdint.h \
    src/leveldb/table/block.h \
    src/leveldb/table/block_builder.h \
    src/leveldb/table/filter_block.h \
    src/leveldb/table/format.h \
    src/leveldb/table/iterator_wrapper.h \
    src/leveldb/table/merger.h \
    src/leveldb/table/two_level_iterator.h \
    src/leveldb/util/arena.h \
    src/leveldb/util/coding.h \
    src/leveldb/util/crc32c.h \
    src/leveldb/util/hash.h \
    src/leveldb/util/histogram.h \
    src/leveldb/util/logging.h \
    src/leveldb/util/mutexlock.h \
    src/leveldb/util/posix_logger.h \
    src/leveldb/util/random.h \
    src/leveldb/util/testharness.h \
    src/leveldb/util/testutil.h \
    src/limitedmap.h \
    src/masternode-payments.h \
    src/masternode-sync.h \
    src/masternode.h \
    src/masternodeconfig.h \
    src/masternodeman.h \
    src/memusage.h \
    src/merkleblock.h \
    src/messagesigner.h \
    src/miner.h \
    src/net.h \
    src/netaddress.h \
    src/netbase.h \
    src/netfulfilledman.h \
    src/net_processing.h \
    src/noui.h \
    src/policy/fees.h \
    src/policy/policy.h \
    src/policy/rbf.h \
    src/pow.h \
    src/prevector.h \
    src/primitives/block.h \
    src/primitives/transaction.h \
    src/privatesend-client.h \
    src/privatesend-server.h \
    src/privatesend-util.h \
    src/privatesend.h \
    src/protocol.h \
    src/pubkey.h \
    src/qt/addressbookpage.h \
    src/qt/addresstablemodel.h \
    src/qt/askpassphrasedialog.h \
    src/qt/bantablemodel.h \
    src/qt/bitcoinaddressvalidator.h \
    src/qt/bitcoinamountfield.h \
    src/qt/bitcoingui.h \
    src/qt/bitcoinunits.h \
    src/qt/clientmodel.h \
    src/qt/coincontroldialog.h \
    src/qt/coincontroltreewidget.h \
    src/qt/csvmodelwriter.h \
    src/qt/darksendconfig.h \
    src/qt/editaddressdialog.h \
    src/qt/guiconstants.h \
    src/qt/guiutil.h \
    src/qt/intro.h \
    src/qt/macdockiconhandler.h \
    src/qt/macnotificationhandler.h \
    src/qt/masternodelist.h \
    src/qt/modaloverlay.h \
    src/qt/networkstyle.h \
    src/qt/notificator.h \
    src/qt/openuridialog.h \
    src/qt/optionsdialog.h \
    src/qt/optionsmodel.h \
    src/qt/overviewpage.h \
    src/qt/paymentrequestplus.h \
    src/qt/paymentserver.h \
    src/qt/peertablemodel.h \
    src/qt/platformstyle.h \
    src/qt/qvalidatedlineedit.h \
    src/qt/qvaluecombobox.h \
    src/qt/receivecoinsdialog.h \
    src/qt/receiverequestdialog.h \
    src/qt/recentrequeststablemodel.h \
    src/qt/rpcconsole.h \
    src/qt/sendcoinsdialog.h \
    src/qt/sendcoinsentry.h \
    src/qt/signverifymessagedialog.h \
    src/qt/splashscreen.h \
    src/qt/test/compattests.h \
    src/qt/test/paymentrequestdata.h \
    src/qt/test/paymentservertests.h \
    src/qt/test/trafficgraphdatatests.h \
    src/qt/test/uritests.h \
    src/qt/trafficgraphdata.h \
    src/qt/trafficgraphwidget.h \
    src/qt/transactiondesc.h \
    src/qt/transactiondescdialog.h \
    src/qt/transactionfilterproxy.h \
    src/qt/transactionrecord.h \
    src/qt/transactiontablemodel.h \
    src/qt/transactionview.h \
    src/qt/utilitydialog.h \
    src/qt/walletframe.h \
    src/qt/walletmodel.h \
    src/qt/walletmodeltransaction.h \
    src/qt/walletview.h \
    src/qt/winshutdownmonitor.h \
    src/random.h \
    src/reverselock.h \
    src/rpc/client.h \
    src/rpc/protocol.h \
    src/rpc/server.h \
    src/scheduler.h \
    src/script/dashconsensus.h \
    src/script/interpreter.h \
    src/script/script.h \
    src/script/script_error.h \
    src/script/sigcache.h \
    src/script/sign.h \
    src/script/standard.h \
    src/secp256k1/contrib/lax_der_parsing.h \
    src/secp256k1/contrib/lax_der_privatekey_parsing.h \
    src/secp256k1/include/secp256k1.h \
    src/secp256k1/include/secp256k1_ecdh.h \
    src/secp256k1/include/secp256k1_recovery.h \
    src/secp256k1/include/secp256k1_schnorr.h \
    src/secp256k1/src/basic-config.h \
    src/secp256k1/src/bench.h \
    src/secp256k1/src/ecdsa.h \
    src/secp256k1/src/ecdsa_impl.h \
    src/secp256k1/src/eckey.h \
    src/secp256k1/src/eckey_impl.h \
    src/secp256k1/src/ecmult.h \
    src/secp256k1/src/ecmult_const.h \
    src/secp256k1/src/ecmult_const_impl.h \
    src/secp256k1/src/ecmult_gen.h \
    src/secp256k1/src/ecmult_gen_impl.h \
    src/secp256k1/src/ecmult_impl.h \
    src/secp256k1/src/field.h \
    src/secp256k1/src/field_10x26.h \
    src/secp256k1/src/field_10x26_impl.h \
    src/secp256k1/src/field_5x52.h \
    src/secp256k1/src/field_5x52_asm_impl.h \
    src/secp256k1/src/field_5x52_impl.h \
    src/secp256k1/src/field_5x52_int128_impl.h \
    src/secp256k1/src/field_impl.h \
    src/secp256k1/src/group.h \
    src/secp256k1/src/group_impl.h \
    src/secp256k1/src/hash.h \
    src/secp256k1/src/hash_impl.h \
    src/secp256k1/src/java/org_bitcoin_NativeSecp256k1.h \
    src/secp256k1/src/modules/ecdh/main_impl.h \
    src/secp256k1/src/modules/ecdh/tests_impl.h \
    src/secp256k1/src/modules/recovery/main_impl.h \
    src/secp256k1/src/modules/recovery/tests_impl.h \
    src/secp256k1/src/modules/schnorr/main_impl.h \
    src/secp256k1/src/modules/schnorr/schnorr.h \
    src/secp256k1/src/modules/schnorr/schnorr_impl.h \
    src/secp256k1/src/modules/schnorr/tests_impl.h \
    src/secp256k1/src/num.h \
    src/secp256k1/src/num_gmp.h \
    src/secp256k1/src/num_gmp_impl.h \
    src/secp256k1/src/num_impl.h \
    src/secp256k1/src/scalar.h \
    src/secp256k1/src/scalar_4x64.h \
    src/secp256k1/src/scalar_4x64_impl.h \
    src/secp256k1/src/scalar_8x32.h \
    src/secp256k1/src/scalar_8x32_impl.h \
    src/secp256k1/src/scalar_impl.h \
    src/secp256k1/src/testrand.h \
    src/secp256k1/src/testrand_impl.h \
    src/secp256k1/src/util.h \
    src/serialize.h \
    src/spentindex.h \
    src/spork.h \
    src/streams.h \
    src/support/allocators/secure.h \
    src/support/allocators/zeroafterfree.h \
    src/support/cleanse.h \
    src/support/pagelocker.h \
    src/sync.h \
    src/test/scriptnum10.h \
    src/test/test_dash.h \
    src/threadinterrupt.h \
    src/threadsafety.h \
    src/timedata.h \
    src/tinyformat.h \
    src/torcontrol.h \
    src/txdb.h \
    src/txmempool.h \
    src/uint256.h \
    src/ui_interface.h \
    src/undo.h \
    src/univalue/include/univalue.h \
    src/univalue/lib/univalue_escapes.h \
    src/univalue/lib/univalue_utffilter.h \
    src/util.h \
    src/utilmoneystr.h \
    src/utilstrencodings.h \
    src/utiltime.h \
    src/validation.h \
    src/validationinterface.h \
    src/version.h \
    src/versionbits.h \
    src/wallet/crypter.h \
    src/wallet/db.h \
    src/wallet/wallet.h \
    src/wallet/walletdb.h \
    src/wallet/wallet_ismine.h \
    src/zmq/zmqabstractnotifier.h \
    src/zmq/zmqconfig.h \
    src/zmq/zmqnotificationinterface.h \
    src/zmq/zmqpublishnotifier.h
FORMS +=  \
    src/qt/forms/addressbookpage.ui \
    src/qt/forms/askpassphrasedialog.ui \
    src/qt/forms/coincontroldialog.ui \
    src/qt/forms/darksendconfig.ui \
    src/qt/forms/debugwindow.ui \
    src/qt/forms/editaddressdialog.ui \
    src/qt/forms/helpmessagedialog.ui \
    src/qt/forms/intro.ui \
    src/qt/forms/masternodelist.ui \
    src/qt/forms/modaloverlay.ui \
    src/qt/forms/openuridialog.ui \
    src/qt/forms/optionsdialog.ui \
    src/qt/forms/overviewpage.ui \
    src/qt/forms/receivecoinsdialog.ui \
    src/qt/forms/receiverequestdialog.ui \
    src/qt/forms/sendcoinsdialog.ui \
    src/qt/forms/sendcoinsentry.ui \
    src/qt/forms/signverifymessagedialog.ui \
    src/qt/forms/transactiondescdialog.ui
SOURCES +=  \
    src/activemasternode.cpp \
    src/addrdb.cpp \
    src/addrman.cpp \
    src/alert.cpp \
    src/amount.cpp \
    src/arith_uint256.cpp \
    src/base58.cpp \
    src/bench/bench.cpp \
    src/bench/bench_dash.cpp \
    src/bench/Examples.cpp \
    src/bip39.cpp \
    src/bloom.cpp \
    src/chain.cpp \
    src/chainparams.cpp \
    src/chainparamsbase.cpp \
    src/checkpoints.cpp \
    src/clientversion.cpp \
    src/coins.cpp \
    src/compat/glibcxx_sanity.cpp \
    src/compat/glibc_compat.cpp \
    src/compat/glibc_sanity.cpp \
    src/compat/strnlen.cpp \
    src/compressor.cpp \
    src/consensus/merkle.cpp \
    src/core_read.cpp \
    src/core_write.cpp \
    src/crypto/aes.cpp \
    src/crypto/aes_helper.c \
    src/crypto/blake.c \
    src/crypto/bmw.c \
    src/crypto/ctaes/bench.c \
    src/crypto/ctaes/ctaes.c \
    src/crypto/ctaes/test.c \
    src/crypto/cubehash.c \
    src/crypto/echo.c \
    src/crypto/groestl.c \
    src/crypto/hmac_sha256.cpp \
    src/crypto/hmac_sha512.cpp \
    src/crypto/jh.c \
    src/crypto/keccak.c \
    src/crypto/luffa.c \
    src/crypto/Lyra2Z/blake.c \
    src/crypto/Lyra2Z/Lyra2.c \
    src/crypto/Lyra2Z/Lyra2Z.c \
    src/crypto/Lyra2Z/Sponge.c \
    src/crypto/ripemd160.cpp \
    src/crypto/scrypt-sse2.cpp \
    src/crypto/scrypt.cpp \
    src/crypto/sha1.cpp \
    src/crypto/sha256.cpp \
    src/crypto/sha512.cpp \
    src/crypto/shavite.c \
    src/crypto/simd.c \
    src/crypto/skein.c \
    src/dash-cli.cpp \
    src/dash-tx.cpp \
    src/dashd.cpp \
    src/dbwrapper.cpp \
    src/drafted/governance-keys.cpp \
    src/drafted/governance-types.cpp \
    src/drafted/governance.new.cpp \
    src/dsnotificationinterface.cpp \
    src/governance-classes.cpp \
    src/governance-object.cpp \
    src/governance-validators.cpp \
    src/governance-vote.cpp \
    src/governance-votedb.cpp \
    src/governance.cpp \
    src/hash.cpp \
    src/hdchain.cpp \
    src/httprpc.cpp \
    src/httpserver.cpp \
    src/init.cpp \
    src/instantx.cpp \
    src/keepass.cpp \
    src/key.cpp \
    src/keystore.cpp \
    src/leveldb/db/autocompact_test.cc \
    src/leveldb/db/builder.cc \
    src/leveldb/db/c.cc \
    src/leveldb/db/corruption_test.cc \
    src/leveldb/db/c_test.c \
    src/leveldb/db/dbformat.cc \
    src/leveldb/db/dbformat_test.cc \
    src/leveldb/db/db_bench.cc \
    src/leveldb/db/db_impl.cc \
    src/leveldb/db/db_iter.cc \
    src/leveldb/db/db_test.cc \
    src/leveldb/db/dumpfile.cc \
    src/leveldb/db/filename.cc \
    src/leveldb/db/filename_test.cc \
    src/leveldb/db/leveldb_main.cc \
    src/leveldb/db/log_reader.cc \
    src/leveldb/db/log_test.cc \
    src/leveldb/db/log_writer.cc \
    src/leveldb/db/memtable.cc \
    src/leveldb/db/repair.cc \
    src/leveldb/db/skiplist_test.cc \
    src/leveldb/db/table_cache.cc \
    src/leveldb/db/version_edit.cc \
    src/leveldb/db/version_edit_test.cc \
    src/leveldb/db/version_set.cc \
    src/leveldb/db/version_set_test.cc \
    src/leveldb/db/write_batch.cc \
    src/leveldb/db/write_batch_test.cc \
    src/leveldb/doc/bench/db_bench_sqlite3.cc \
    src/leveldb/doc/bench/db_bench_tree_db.cc \
    src/leveldb/helpers/memenv/memenv.cc \
    src/leveldb/helpers/memenv/memenv_test.cc \
    src/leveldb/issues/issue178_test.cc \
    src/leveldb/issues/issue200_test.cc \
    src/leveldb/port/port_posix.cc \
    src/leveldb/port/port_win.cc \
    src/leveldb/table/block.cc \
    src/leveldb/table/block_builder.cc \
    src/leveldb/table/filter_block.cc \
    src/leveldb/table/filter_block_test.cc \
    src/leveldb/table/format.cc \
    src/leveldb/table/iterator.cc \
    src/leveldb/table/merger.cc \
    src/leveldb/table/table.cc \
    src/leveldb/table/table_builder.cc \
    src/leveldb/table/table_test.cc \
    src/leveldb/table/two_level_iterator.cc \
    src/leveldb/util/arena.cc \
    src/leveldb/util/arena_test.cc \
    src/leveldb/util/bloom.cc \
    src/leveldb/util/bloom_test.cc \
    src/leveldb/util/cache.cc \
    src/leveldb/util/cache_test.cc \
    src/leveldb/util/coding.cc \
    src/leveldb/util/coding_test.cc \
    src/leveldb/util/comparator.cc \
    src/leveldb/util/crc32c.cc \
    src/leveldb/util/crc32c_test.cc \
    src/leveldb/util/env.cc \
    src/leveldb/util/env_posix.cc \
    src/leveldb/util/env_test.cc \
    src/leveldb/util/env_win.cc \
    src/leveldb/util/filter_policy.cc \
    src/leveldb/util/hash.cc \
    src/leveldb/util/hash_test.cc \
    src/leveldb/util/histogram.cc \
    src/leveldb/util/logging.cc \
    src/leveldb/util/options.cc \
    src/leveldb/util/status.cc \
    src/leveldb/util/testharness.cc \
    src/leveldb/util/testutil.cc \
    src/masternode-payments.cpp \
    src/masternode-sync.cpp \
    src/masternode.cpp \
    src/masternodeconfig.cpp \
    src/masternodeman.cpp \
    src/merkleblock.cpp \
    src/messagesigner.cpp \
    src/miner.cpp \
    src/net.cpp \
    src/netaddress.cpp \
    src/netbase.cpp \
    src/netfulfilledman.cpp \
    src/net_processing.cpp \
    src/noui.cpp \
    src/policy/fees.cpp \
    src/policy/policy.cpp \
    src/policy/rbf.cpp \
    src/pow.cpp \
    src/primitives/block.cpp \
    src/primitives/transaction.cpp \
    src/privatesend-client.cpp \
    src/privatesend-server.cpp \
    src/privatesend-util.cpp \
    src/privatesend.cpp \
    src/protocol.cpp \
    src/pubkey.cpp \
    src/qt/addressbookpage.cpp \
    src/qt/addresstablemodel.cpp \
    src/qt/askpassphrasedialog.cpp \
    src/qt/bantablemodel.cpp \
    src/qt/bitcoinaddressvalidator.cpp \
    src/qt/bitcoinamountfield.cpp \
    src/qt/bitcoingui.cpp \
    src/qt/bitcoinunits.cpp \
    src/qt/clientmodel.cpp \
    src/qt/coincontroldialog.cpp \
    src/qt/coincontroltreewidget.cpp \
    src/qt/csvmodelwriter.cpp \
    src/qt/darksendconfig.cpp \
    src/qt/dash.cpp \
    src/qt/dashstrings.cpp \
    src/qt/editaddressdialog.cpp \
    src/qt/guiutil.cpp \
    src/qt/intro.cpp \
    src/qt/masternodelist.cpp \
    src/qt/modaloverlay.cpp \
    src/qt/networkstyle.cpp \
    src/qt/notificator.cpp \
    src/qt/openuridialog.cpp \
    src/qt/optionsdialog.cpp \
    src/qt/optionsmodel.cpp \
    src/qt/overviewpage.cpp \
    src/qt/paymentrequestplus.cpp \
    src/qt/paymentserver.cpp \
    src/qt/peertablemodel.cpp \
    src/qt/platformstyle.cpp \
    src/qt/qvalidatedlineedit.cpp \
    src/qt/qvaluecombobox.cpp \
    src/qt/receivecoinsdialog.cpp \
    src/qt/receiverequestdialog.cpp \
    src/qt/recentrequeststablemodel.cpp \
    src/qt/rpcconsole.cpp \
    src/qt/sendcoinsdialog.cpp \
    src/qt/sendcoinsentry.cpp \
    src/qt/signverifymessagedialog.cpp \
    src/qt/splashscreen.cpp \
    src/qt/test/compattests.cpp \
    src/qt/test/paymentservertests.cpp \
    src/qt/test/test_main.cpp \
    src/qt/test/trafficgraphdatatests.cpp \
    src/qt/test/uritests.cpp \
    src/qt/trafficgraphdata.cpp \
    src/qt/trafficgraphwidget.cpp \
    src/qt/transactiondesc.cpp \
    src/qt/transactiondescdialog.cpp \
    src/qt/transactionfilterproxy.cpp \
    src/qt/transactionrecord.cpp \
    src/qt/transactiontablemodel.cpp \
    src/qt/transactionview.cpp \
    src/qt/utilitydialog.cpp \
    src/qt/walletframe.cpp \
    src/qt/walletmodel.cpp \
    src/qt/walletmodeltransaction.cpp \
    src/qt/walletview.cpp \
    src/qt/winshutdownmonitor.cpp \
    src/random.cpp \
    src/rest.cpp \
    src/rpc/blockchain.cpp \
    src/rpc/client.cpp \
    src/rpc/governance.cpp \
    src/rpc/masternode.cpp \
    src/rpc/mining.cpp \
    src/rpc/misc.cpp \
    src/rpc/net.cpp \
    src/rpc/protocol.cpp \
    src/rpc/rawtransaction.cpp \
    src/rpc/server.cpp \
    src/scheduler.cpp \
    src/script/dashconsensus.cpp \
    src/script/interpreter.cpp \
    src/script/script.cpp \
    src/script/script_error.cpp \
    src/script/sigcache.cpp \
    src/script/sign.cpp \
    src/script/standard.cpp \
    src/secp256k1/contrib/lax_der_parsing.c \
    src/secp256k1/contrib/lax_der_privatekey_parsing.c \
    src/secp256k1/src/bench_ecdh.c \
    src/secp256k1/src/bench_internal.c \
    src/secp256k1/src/bench_recover.c \
    src/secp256k1/src/bench_schnorr_verify.c \
    src/secp256k1/src/bench_sign.c \
    src/secp256k1/src/bench_verify.c \
    src/secp256k1/src/gen_context.c \
    src/secp256k1/src/java/org_bitcoin_NativeSecp256k1.c \
    src/secp256k1/src/secp256k1.c \
    src/secp256k1/src/tests.c \
    src/sendalert.cpp \
    src/spork.cpp \
    src/support/cleanse.cpp \
    src/support/pagelocker.cpp \
    src/sync.cpp \
    src/test/accounting_tests.cpp \
    src/test/addrman_tests.cpp \
    src/test/alert_tests.cpp \
    src/test/allocator_tests.cpp \
    src/test/arith_uint256_tests.cpp \
    src/test/base32_tests.cpp \
    src/test/base58_tests.cpp \
    src/test/base64_tests.cpp \
    src/test/bip32_tests.cpp \
    src/test/bip39_tests.cpp \
    src/test/bloom_tests.cpp \
    src/test/bswap_tests.cpp \
    src/test/cachemap_tests.cpp \
    src/test/cachemultimap_tests.cpp \
    src/test/checkblock_tests.cpp \
    src/test/coins_tests.cpp \
    src/test/compress_tests.cpp \
    src/test/crypto_tests.cpp \
    src/test/dbwrapper_tests.cpp \
    src/test/DoS_tests.cpp \
    src/test/getarg_tests.cpp \
    src/test/governance_validators_tests.cpp \
    src/test/hash_tests.cpp \
    src/test/key_tests.cpp \
    src/test/limitedmap_tests.cpp \
    src/test/main_tests.cpp \
    src/test/mempool_tests.cpp \
    src/test/merkle_tests.cpp \
    src/test/miner_tests.cpp \
    src/test/multisig_tests.cpp \
    src/test/netbase_tests.cpp \
    src/test/net_tests.cpp \
    src/test/pmt_tests.cpp \
    src/test/policyestimator_tests.cpp \
    src/test/pow_tests.cpp \
    src/test/prevector_tests.cpp \
    src/test/ratecheck_tests.cpp \
    src/test/reverselock_tests.cpp \
    src/test/rpc_tests.cpp \
    src/test/rpc_wallet_tests.cpp \
    src/test/sanity_tests.cpp \
    src/test/scheduler_tests.cpp \
    src/test/scriptnum_tests.cpp \
    src/test/script_P2PKH_tests.cpp \
    src/test/script_P2SH_tests.cpp \
    src/test/script_tests.cpp \
    src/test/serialize_tests.cpp \
    src/test/sighash_tests.cpp \
    src/test/sigopcount_tests.cpp \
    src/test/skiplist_tests.cpp \
    src/test/streams_tests.cpp \
    src/test/test_dash.cpp \
    src/test/timedata_tests.cpp \
    src/test/transaction_tests.cpp \
    src/test/txvalidationcache_tests.cpp \
    src/test/uint256_tests.cpp \
    src/test/univalue_tests.cpp \
    src/test/util_tests.cpp \
    src/test/versionbits_tests.cpp \
    src/threadinterrupt.cpp \
    src/timedata.cpp \
    src/torcontrol.cpp \
    src/txdb.cpp \
    src/txmempool.cpp \
    src/uint256.cpp \
    src/univalue/gen/gen.cpp \
    src/univalue/lib/univalue.cpp \
    src/univalue/lib/univalue_read.cpp \
    src/univalue/lib/univalue_write.cpp \
    src/univalue/test/unitester.cpp \
    src/util.cpp \
    src/utilmoneystr.cpp \
    src/utilstrencodings.cpp \
    src/utiltime.cpp \
    src/validation.cpp \
    src/validationinterface.cpp \
    src/versionbits.cpp \
    src/wallet/crypter.cpp \
    src/wallet/db.cpp \
    src/wallet/rpcdump.cpp \
    src/wallet/rpcwallet.cpp \
    src/wallet/test/wallet_tests.cpp \
    src/wallet/wallet.cpp \
    src/wallet/walletdb.cpp \
    src/wallet/wallet_ismine.cpp \
    src/zmq/zmqabstractnotifier.cpp \
    src/zmq/zmqnotificationinterface.cpp \
    src/zmq/zmqpublishnotifier.cpp
RESOURCES +=  \
    src/qt/dash.qrc \
    src/qt/dash_locale.qrc
TRANSLATIONS +=  \
    src/dash-cli-res.rc \
    src/dash-tx-res.rc \
    src/dashd-res.rc \
    src/qt/locale/dash_bg.ts \
    src/qt/locale/dash_de.ts \
    src/qt/locale/dash_en.ts \
    src/qt/locale/dash_es.ts \
    src/qt/locale/dash_fi.ts \
    src/qt/locale/dash_fr.ts \
    src/qt/locale/dash_it.ts \
    src/qt/locale/dash_ja.ts \
    src/qt/locale/dash_pl.ts \
    src/qt/locale/dash_pt.ts \
    src/qt/locale/dash_ru.ts \
    src/qt/locale/dash_sk.ts \
    src/qt/locale/dash_sv.ts \
    src/qt/locale/dash_vi.ts \
    src/qt/locale/dash_zh_CN.ts \
    src/qt/locale/dash_zh_TW.ts \
    src/qt/res/dash-qt-res.rc