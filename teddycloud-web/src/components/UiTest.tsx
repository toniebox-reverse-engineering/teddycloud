import { Breadcrumb, DatePicker, Layout, Menu, MenuProps } from "antd";
import Sider from "antd/es/layout/Sider";
import { Content } from "antd/es/layout/layout";
import { LaptopOutlined, UserOutlined } from "@ant-design/icons";
import React from "react";
import { useTranslation } from "react-i18next";

const subnav: MenuProps["items"] = [
  {
    key: "sub",
    label: "subnav",
    children: [
      { key: "1", label: "option1" },
      { key: "2", label: "option2" },
      { key: "3", label: "option3" },
      { key: "4", label: "option4" },
    ],
    icon: React.createElement(UserOutlined),
  },
  {
    key: "sub2",
    label: "subnav",
    children: [
      { key: "1", label: "option1" },
      { key: "2", label: "option2" },
      { key: "3", label: "option3" },
      { key: "4", label: "option4" },
    ],
    icon: React.createElement(LaptopOutlined),
  },
];

export const UiTest = () => {
  const { t } = useTranslation();

  return (
    <>
      <Sider width={200} style={{ background: "#FFF" }}>
        <Menu
          mode="inline"
          //defaultSelectedKeys={["1"]}
          //defaultOpenKeys={["sub1"]}
          style={{ height: "100%", borderRight: 0 }}
          items={subnav}
        />
      </Sider>
      <Layout style={{ padding: "0 24px 24px" }}>
        <Breadcrumb style={{ margin: "16px 0" }}>
          <Breadcrumb.Item>Home</Breadcrumb.Item>
          <Breadcrumb.Item>List</Breadcrumb.Item>
          <Breadcrumb.Item>App</Breadcrumb.Item>
        </Breadcrumb>
        <Content
          style={{
            padding: 24,
            margin: 0,
            minHeight: 280,
            background: "#FFF",
          }}
        >
          <p>{t(`welcome.title`)}</p>
          <p>Sample datepicker from ant design:</p>
          <DatePicker />
        </Content>
      </Layout>
    </>
  );
};
