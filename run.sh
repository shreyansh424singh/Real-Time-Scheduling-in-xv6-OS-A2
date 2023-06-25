cd xv6-public
make clean
tar czvf assignment2_easy_2020CS50415_2020CS10385.tar.gz *
mkdir check_scripts
tar xzvf check_scripts.tar.gz -C check_scripts
cp assignment2_easy_2020CS50415_2020CS10385.tar.gz check_scripts
cd check_scripts
bash check.sh assignment2_easy_2020CS50415_2020CS10385.tar.gz
cd ..
rm -r check_scripts
make clean