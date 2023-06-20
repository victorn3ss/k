import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show PlatformException;
import 'package:flutter/services.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({Key? key}) : super(key: key);

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    const appTitle = 'KPLUS Generator';

    return MaterialApp(
      title: appTitle,
      theme: ThemeData(
        primarySwatch: Colors.blue,
      ),
      home: Scaffold(
        appBar: AppBar(
          title: const Text(appTitle),
        ),
        body: const MyCustomForm(),
      ),
    );
  }
}

class MyCustomForm extends StatefulWidget {
  const MyCustomForm({Key? key}) : super(key: key);

  @override
  MyCustomFormState createState() {
    return MyCustomFormState();
  }
}

// Create a corresponding State class.
// This class holds data related to the form.
class MyCustomFormState extends State<MyCustomForm> {
  // Create a global key that uniquely identifies the Form widget
  // and allows validation of the form.
  //
  // Note: This is a GlobalKey<FormState>,
  // not a GlobalKey<MyCustomFormState>.
  final _formKey = GlobalKey<FormState>();
  final outputController = TextEditingController();
  var output;

  static const platform = MethodChannel('generator');

  @override
  Widget build(BuildContext context) {
    String accountNumber = '';
    String documentId = '';
    String pin = '';

    return Form(
      key: _formKey,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 16),
            child: TextFormField(
              decoration: const InputDecoration(
                border: UnderlineInputBorder(),
                labelText: 'กรอกเลขบัญชี',
              ),
              validator: (value) {
                if (value == null || value.isEmpty) {
                  return 'โปรดกรอกเลขบัญชี';
                }
                var exp = RegExp(r"^[0-9]{10}$");
                if (!exp.hasMatch(value)) {
                  return 'เลขบัญชีไม่ถูกต้อง';
                }

                return null;
              },
              onSaved: (String? v) {
                accountNumber = v ?? '';
              },
            ),
          ),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 16),
            child: TextFormField(
              decoration: const InputDecoration(
                border: UnderlineInputBorder(),
                labelText: 'กรอกเลขบัตรประชาชน',
              ),
              validator: (value) {
                if (value == null || value.isEmpty) {
                  return 'โปรดกรอกเลขบัตรประชาชน';
                }
                var exp = RegExp(r"^[0-9]{13}$");
                if (!exp.hasMatch(value)) {
                  return 'เลขบัตรประชาชนไม่ถูกต้อง';
                }

                return null;
              },
              onSaved: (String? v) {
                documentId = v ?? '';
              },
            ),
          ),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 16),
            child: TextFormField(
              decoration: const InputDecoration(
                border: UnderlineInputBorder(),
                labelText: 'กรอก PIN',
              ),
              validator: (value) {
                if (value == null || value.isEmpty) {
                  return 'โปรดกกรอก PIN';
                }
                var exp = RegExp(r"^[0-9]{6}$");
                if (!exp.hasMatch(value)) {
                  return 'PIN ไม่ถูกต้อง';
                }

                return null;
              },
              onSaved: (String? v) {
                pin = v ?? '';
              },
            ),
          ),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 16.0),
            child: ElevatedButton(
              onPressed: () async {
                if (_formKey.currentState!.validate()) {
                  _formKey.currentState?.save();

                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Loading...')),
                  );

                  try {
                    var arguments = {};
                    arguments["accountNumber"] = accountNumber;
                    arguments["documentId"] = documentId;
                    arguments["pin"] = pin;

                    var json = await platform.invokeMethod('register', arguments);
                    setState(() {
                      output = jsonDecode(json);
                      outputController.text = jsonEncode(output['state']);
                    });

                    ScaffoldMessenger.of(context).hideCurrentSnackBar();
                  } on PlatformException catch (e) {
                    if (e.message != null) {
                      outputController.text = e.message ?? '';

                      ScaffoldMessenger.of(context).hideCurrentSnackBar();
                      ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(content: Text(e.message ?? '')),
                      );
                    }
                  }
                }
              },
              child: const Text('สร้าง'),
            ),
          ),
          if (output != null) ...[
            Padding(
              padding:
              const EdgeInsets.symmetric(horizontal: 8, vertical: 16.0),
              child: Text(
                "Email: ${output['extra']?['emailAddress']}\n",
                textAlign: TextAlign.left,
              ),
            ),
            Padding(
              padding:
              const EdgeInsets.symmetric(horizontal: 8, vertical: 16.0),
              child: TextField(
                controller: outputController,
                keyboardType: TextInputType.multiline,
                maxLines: 4,
                enabled: false,
              ),
            ),
            Padding(
              padding:
              const EdgeInsets.symmetric(horizontal: 8, vertical: 16.0),
              child: ElevatedButton(
                onPressed: () async {
                  Clipboard.setData(
                      ClipboardData(text: outputController.text));
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('คัดลอกสำเร็จ')),
                  );
                },
                child: const Text('คัดลอก'),
              ),
            ),
          ]
        ],
      ),
    );
  }
}
