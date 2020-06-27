cd /home/antti/QuickChat/
git clone https://github.com/EskelinenAntti/QuickChat.git temp
cd temp
npm run build
cd ..
rm -rf app
mv temp app
systemctl restart quick-chat