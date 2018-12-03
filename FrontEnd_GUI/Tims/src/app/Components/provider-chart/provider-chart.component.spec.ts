import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { ProviderChartComponent } from './provider-chart.component';

describe('ProviderChartComponent', () => {
  let component: ProviderChartComponent;
  let fixture: ComponentFixture<ProviderChartComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ ProviderChartComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(ProviderChartComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
