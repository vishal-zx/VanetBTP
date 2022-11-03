//
// Copyright (C) 2018 Christoph Sommer <sommer@ccs-labs.org>
//
// Documentation for these modules is at http://veins.car2x.org/
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//

#include "veins_inet/VeinsInetSampleApplication.h"

#include "inet/common/ModuleAccess.h"
#include "inet/common/packet/Packet.h"
#include "inet/common/TagBase_m.h"
#include "inet/common/TimeTag_m.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/transportlayer/contract/udp/UdpControlInfo_m.h"

#include "veins_inet/VeinsInetSampleMessage_m.h"

#include "rsa.h"
#include "pbc.h"
#include "osrng.h"
//#include "veins_inet/protocol.h"

using namespace inet;

Define_Module(VeinsInetSampleApplication);

VeinsInetSampleApplication::VeinsInetSampleApplication()
{
}

bool VeinsInetSampleApplication::startApplication()
{
    // host[0] should stop at t=20s
    if (getParentModule()->getIndex() == 0) {
        auto callback = [this]() {
            getParentModule()->getDisplayString().setTagArg("i", 1, "red");

            traciVehicle->setSpeed(0);

            auto payload = makeShared<VeinsInetSampleMessage>();
            payload->setChunkLength(B(100));
            payload->setRoadId(traciVehicle->getRoadId().c_str());
            timestampPayload(payload);

            /*
            //----RSA Starting-----------
            std::string s = "AccidentLMAO";

            CryptoPP::InvertibleRSAFunction params1;
            CryptoPP::AutoSeededRandomPool prng1;

            params1.SetPublicExponent(7);
            params1.GenerateRandomWithKeySize(prng1, 32);

            const CryptoPP::Integer& npb = params1.GetModulus();
            const CryptoPP::Integer& epb = params1.GetPublicExponent();

            CryptoPP::RSA::PublicKey pubKey;
            pubKey.Initialize(npb, epb);

            CryptoPP::Integer c, m;
            // Encrypt
            m = CryptoPP::Integer((const CryptoPP::byte *)s.data(), s.size());
            c = pubKey.ApplyFunction(m);
            std::stringstream ss;
            ss << c;
            std::string xs = ss.str();
            //----RSA End-----------
            */
            //char** s = {"jsfngleq", "smnfl"};
            //mainn(4, s);
            CryptoPP::Integer n("0xbeaadb3d839f3b5f"), e("0x11"), d("0x21a5ae37b9959db9");
            CryptoPP::RSA::PublicKey pubKey;
            pubKey.Initialize(n, e);
            CryptoPP::Integer m,c;
            std::string message = "secret";
            std::cout<<"message: "<<message<<endl;
            m = CryptoPP::Integer((const CryptoPP::byte *)message.data(), message.size());
            std::cout<<"m: "<<std::hex<<m<<endl;
            c = pubKey.ApplyFunction(m);
            std::cout<<"c: "<<c<<endl;
            std::stringstream ss;
            ss<<c;

            auto packet = createPacket(ss.str());
            packet->insertAtBack(payload);
            sendPacket(std::move(packet));

            // host should continue after 30s
            auto callback = [this]() {
                traciVehicle->setSpeed(-1);
            };
            timerManager.create(veins::TimerSpecification(callback).oneshotIn(SimTime(30, SIMTIME_S)));
        };
        timerManager.create(veins::TimerSpecification(callback).oneshotAt(SimTime(20, SIMTIME_S)));
    }haveForwarded;

    return true;
}

bool VeinsInetSampleApplication::stopApplication()
{
    return true;
}

VeinsInetSampleApplication::~VeinsInetSampleApplication()
{
}

void VeinsInetSampleApplication::processPacket(std::shared_ptr<inet::Packet> pk)
{
    auto payload = pk->peekAtFront<VeinsInetSampleMessage>();

    EV_INFO << "Received packet: " << payload << endl;

    getParentModule()->getDisplayString().setTagArg("i", 1, "green");

    traciVehicle->changeRoute(payload->getRoadId(), 999.9);

    if (haveForwarded) return;

    /*
    //----RSA Starting-----------
    auto ss1 = pk.get();
    auto encrStr = ss1->getName();

    CryptoPP::InvertibleRSAFunction params2;
    CryptoPP::AutoSeededRandomPool prng2;

    params2.SetPublicExponent(7);
    params2.GenerateRandomWithKeySize(prng2, 32);

    const CryptoPP::Integer& npv = params2.GetModulus();
    const CryptoPP::Integer& dpv = params2.GetPrivateExponent();
    const CryptoPP::Integer& epv = params2.GetPublicExponent();

    CryptoPP::RSA::PrivateKey privKey;
    privKey.Initialize(npv, epv, dpv);

    CryptoPP::Integer r;
    std::string recovered;
    // Decrypt

    CryptoPP::Integer estrnum = std::stol(encrStr);
    r = privKey.CalculateInverse(prng2, estrnum);
    std::size_t req = r.MinEncodedSize();
    recovered.resize(req);
    r.Encode((CryptoPP::byte *)recovered.data(), recovered.size());
    std::cout<<"recovered: "<<recovered<<endl;

    //----RSA End-----------
    */

    auto ss1 = pk.get();
    auto cS = ss1->getName();
    std::stringstream ss;
    ss<<cS;

    CryptoPP::Integer n("0xbeaadb3d839f3b5f"), e("0x11"), d("0x21a5ae37b9959db9");
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::RSA::PrivateKey privKey;
    privKey.Initialize(n, e, d);
    CryptoPP::Integer c(ss.str().data()), r;
    std::string recovered;
    r = privKey.CalculateInverse(prng, c);
    std::cout<<"r: "<<std::hex<<r<<endl;
    std::size_t req = r.MinEncodedSize();
    recovered.resize(req);
    r.Encode((CryptoPP::byte *)recovered.data(), recovered.size());
    std::cout<<"recovered: "<<recovered<<endl;

    auto packet = createPacket("secret");
    packet->insertAtBack(payload);
    sendPacket(std::move(packet));

    haveForwarded = true;
}
